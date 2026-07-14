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
pre-commit check. Each name keeps only an `authoritative_pattern_metadata_ref`; the referenced pattern holds the full
evidence and provenance once, so repeated name metadata cannot consume the 32 MiB canonical-bank budget without adding
detection coverage. Deep validation still checks the complete bank, including draft material, while the native compile
gate compiles exactly the active production surface used for extraction.

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
`nerb export-enron-capacity` invocations fail closed outside that bootstrap. For a production run, that launcher remains
resident as the resource supervisor while a separate isolated worker executes the capacity workload.

The capacity decision uses these frozen resource gates:

| Resource gate | Passing requirement |
| --- | --- |
| Preflight free space | At least 25 GiB on each distinct output and attempt-ledger filesystem |
| Observed owned and temporary high-water | At most 20 GiB |
| Sampled runtime free-space floor | At least 5 GiB on every monitored filesystem at every completed sample |
| Total attempt runtime | At most 4 hours |
| Phase throughput | At least 100 source rows per second in every phase |
| Effective RSS cap | `min(8 GiB, 75% of physical memory)` |
| Passing observed RSS | At most 75% of the effective RSS cap |
| Resource acquisition duration | At most 500 ms for each complete RSS and filesystem sample |
| Resource-observation wall gap | At most 500 ms between completed valid samples through the terminal observation |
| Verified-work liveness gap | At most 30 seconds during every phase |

The launcher owns the nominal 100 ms RSS and filesystem sampling loop, so workload code holding the worker interpreter's
GIL cannot delay the sampler. A sample advances the completion-to-completion cadence only after both acquisitions validate.
Each acquisition and each gap between completed valid samples has its own exact 500 ms fail-closed limit; a partial or
malformed sample advances neither cadence nor the successful-observation count. Forced samples serialize with the periodic
loop at worker checkpoints and boundaries, and the terminal sample must be acknowledged before the launcher accepts a
successful worker response. Probe acquisition ends before sample publication, so socket backpressure cannot be
misreported as slow RSS or filesystem measurement; publication that prevents the next completed sample still fails the
cadence as a protocol error. Terminal success requires the final frame and clean stream EOF in both directions. Parsed,
partial, or later bytes after either terminal frame fail closed.

An acquisition over 500 ms is an invalid sample and deterministically reports `resource_acquisition_timeout` before any
RSS, disk, cadence, runtime, terminal-leak, or fallback failure observed by that acquisition. Acquisitions completed within
the deadline retain RSS, runtime free-disk, worker-owned disk, cadence, runtime, terminal-leak, then fallback precedence.

The fresh worker binds its clean immutable HEAD, tracked-file inventory, CPU/memory facts, resource preflight, attempt
ledger, and private-output policy before installing the process fence. An output inside a Git workspace must use a wholly
ignored parent directory; exact rules for only the final and staging names are insufficient because fail-closed cleanup
may retain an owner-only tombstone containing wiped filenames. The worker validates the final path and that parent, creates
and pins the still-empty ignored stage, then installs and runtime-attests the OS process-creation fence before it preloads
tracked workload modules, reads private corpus inputs, writes corpus-derived bytes, or starts workload code. Linux uses a
seccomp filter that allows thread clones but rejects process creation; macOS uses a literal `deny process-fork` sandbox
profile. The macOS API is treated as a runtime-attested platform boundary: an unavailable profile or a failed
fork/spawn canary fails closed. Every later workload thread inherits the fence, so no workload process can detach from
both ancestry and the isolated group. Post-fence identity checks read the cached immutable inventory and current file
bytes without spawning; the same identity is proven against the public recorded-commit verifier before containment.
Portable verification also binds the attested containment mode and lowercase architecture to the recorded runtime kernel
and architecture, so a self-consistent policy from another platform cannot be relabeled as this run's evidence.
The ignored-parent capability binds its pre-fence policy, requested and effective workspace roots, and parent identity;
it assumes a trusted, quiescent host does not concurrently change `.gitignore`, `.git/info/exclude`, global Git excludes,
related Git configuration, or the bound output-parent namespace before cleanup. Cleanup rechecks the public parent path,
ownership, and owner-only mode against its pinned descriptor and fails rather than publishing a tombstone after a rename,
substitution, or permission change. Use an output parent outside every Git workspace when the Git-policy assumption cannot
be guaranteed.

Before terminal success can reach the worker, the launcher takes one process-table snapshot containing PID, parent,
process group, start identity, and RSS. Any remaining worker descendant or isolated-group member produces
`worker_process_leak`. The terminal audit never signals a bare PID after a racy identity check: the frozen residual RSS
remains part of the terminal peak, the worker retains authority to wipe the staged run and append a failed receipt, and
the launcher performs cooperative cleanup followed by isolated process-group escalation. That later cleanup is a
backstop, not the first point at which a leak is judged.

Reported RSS covers the complete launcher-root execution tree, including the launcher observer, isolated worker, and live
worker descendants. Each sample takes the maximum of the current live-tree reading and a conservative kernel high-water
bound that combines launcher and worker root/reaped-child maxima. Those maxima can come from different instants and can
overestimate an instantaneous tree peak. Sampling also cannot prove that no shorter-lived RSS spike occurred between
observations. The report freezes its resource totals before report serialization and is explicitly pre-terminal evidence,
not a decision by itself. The terminal attempt receipt can therefore contain a higher, deliberately conservative RSS peak,
lower free-space reading, larger valid-sample count, or larger cadence gap after report fsync and promotion; those values
must still satisfy the same exact resource limits bound into the report policy.

Private-tree measurement stays in the workload worker rather than the 100 ms launcher sampling lane. The worker performs
descriptor-relative exact logical-byte and privacy/inode validation at semantic checkpoints, phase and transaction
boundaries, the final staging boundary, and the promoted final-tree boundary; verified activity additionally triggers a
rate-limited exact scan. The reported owned-disk high-water is the maximum of those exact observations, the exact
report-bound final size, and the sampled decrease in free space on the shared output filesystem. The filesystem delta is
conservative when unrelated activity consumes space, but it is not an attribution of every filesystem change to NERB.
Neither 100 ms free-space sampling nor boundary/checkpoint tree scans establish a strict high-water for a private file
created and removed entirely between observations. The evidence therefore makes no strict transient private-tree
high-water claim. The terminal receipt binds the exact promoted final-tree byte count, while the report retains the
broader observed high-water used by the 20 GiB gate.

The run requires the exact locked reader set (`datasets==5.0.0`, `huggingface-hub==1.23.0`, `httpx==0.28.1`,
`fsspec==2026.4.0`, and `pyarrow==25.0.0`). It records a path-free hash of the complete installed name/version inventory
and hashes every regular in-root package or `.dist-info` file listed by those five distributions, excluding bytecode
caches and external `..` entries such as installed console scripts. It proves each required top-level reader module originates below its hashed
distribution root; the distribution inventory covers submodule source files but does not separately attest every loaded
submodule origin. It also binds the checked-in `pyproject.toml` plus `uv.lock`.

Those hashes identify the bytes that were observed; they do not compare them with a precommitted wheel attestation. A
production run therefore requires a trusted, access-controlled host and a fresh uv-managed install from the checked-in
lock. A locally modified package that retains its version metadata produces a different observed hash but is not rejected
against a known-good package digest. Dependencies below `httpx` remain lock-and-version bound rather than individually
byte-attested. Both limitations are explicit in portable evidence.

Reader provenance is metadata-only before the preparation phase: neither `datasets` nor its Hub, filesystem, or Arrow
dependencies may load before the phase owns its runtime tree. The first import occurs after HOME, temporary, XDG,
dataset/module/download/extraction, Hub/assets/Xet, transformer, and credential paths are redirected to phase-owned
private roots. The run fixes the official Hub endpoint, disables offline mode, ambient credentials, implicit tokens,
Xet, telemetry, and cache symlinks, passes `token=False` plus the phase cache explicitly, and uses umask `077`. It
validates the effective library constants before and after source consumption without publishing an absolute path or
credential value. The pinned Hub reader explicitly requests group-shared cache locks, so the remote-preparation boundary
also validates that exact dependency binding and substitutes owner-only mode `0600` for both its file-lock path and
soft-lock fallback. Lock paths are restricted to the phase-owned reader roots, the adapter remains active through lazy
source exhaustion, and the original dependency bindings must be restored exactly. The reader-isolation commitment binds
the adapter policy, effective lock mode, and owner-only result; the private-tree scanner continues to reject every
group- or other-accessible file without a lock-file exception.

Semantic record checkpoints remain every 10,000 records. Separate liveness activity is tied to genuine work every 1,000
records, which is at most 10 seconds at the 100-record/second acceptance floor. During the remote read, the exact pinned
Hub client also emits payload-free activity on response headers and nonempty response chunks; it captures no URL, header,
response metadata, or content. A successful wrapper close immediately drops its underlying stream reference. Every
wrapped response stream and client must prove a successful delegated close before the Hub factory and session are
restored; cleanup then removes the installed hooks and instance close wrapper and clears adapter-owned client/stream
references. Any close exception fails the run even if the dependency already marks the object closed. Those activity
calls can refresh liveness frequently while activity-triggered exact private-tree scans remain rate-limited to once every
5 seconds; the separate launcher continues RSS and filesystem sampling at its nominal 100 ms cadence. Production phases
do not use a timer-only heartbeat, so an operation with no verified work signal still fails the 30-second watchdog. Long
SQLite work uses the connection's VM progress handler, so index
construction and sorted joins report executed database work without a timer thread or an inferred filesystem signal.
The handler must be removed successfully before its connection owner closes the spool; an unproven removal fails closed.

When the liveness gate fails, the CLI appends one closed aggregate diagnostic to stderr: phase, fixed failure origin, last
accepted progress kind, rejected progress kind, last completed-record count, checkpoint and progress-signal counts, phase
wall time, and rejected gap. A resource-observation gap instead reports only its closed sample kind, sequence, measured
gap and limit, acquisition/component durations and retries, and scheduler lateness. Neither diagnostic can contain paths,
exception text, identifiers, or document-derived values. Attempt receipts intentionally remain code-only; capture the
one-time CLI stderr diagnostic when investigating a failed production attempt.

Observer or worker-channel failure first asks the isolated worker watchdog to unwind through the worker's retained
transaction and cleanup authority. The launcher allows at most one absolute 60-second cooperative-cleanup interval from
the first failure observation; later pipe, publication, or finalization handling cannot restart that allowance. It then
terminates any residual isolated process group and proves the group is gone before recovery reads or removes private
state. Hard termination is only a fail-safe escalation—it cannot recreate cleanup authority in a process that did not
cooperate—so any unproven cleanup fails the attempt rather than producing decision evidence.

Before a production capacity attempt, run the same-host observer soak from the exact candidate revision:

```shell
uv sync --locked --no-default-groups --group enron-capacity --python 3.13 --reinstall-package nerb
uv run --locked --no-default-groups --group enron-capacity --no-sync --python 3.13 \
  python -I -S -B scripts/run_enron_capacity.py resource-observer-soak --require-decision-grade
```

`--require-decision-grade` preserves the same aggregate JSON on standard output but exits successfully only when that
report sets `decision_grade: true`. Omit the flag for shortened smoke runs whose exit status should reflect `ok` instead.
If the aggregate report must be retained, redirect standard output to an ignored owner-only artifact while preserving the
script's exit status; do not pipe it through a command that can mask a failed decision gate.

Its default positive case runs for 30 minutes over an owner-only synthetic tree with at least 10,000 retained files while
also exercising SQLite, PyArrow, native Rust scans, child/grandchild churn, and repeated 850 ms intervals
where the worker holds the GIL in C. It reports aggregate-only p50/p95/p99/max acquisition, completion-gap, scheduler,
CPU, memory, and cleanup evidence. A separate exact 501 ms injected acquisition must produce
`resource_acquisition_timeout` and clean teardown. Both the requested and measured positive duration must reach 30
minutes, PyArrow must be available and complete work, every positive and negative-control gate must pass, and cleanup
must be proven before the report can set `decision_grade: true`. The unchanged production hard gates remain 500 ms, but
decision-grade evidence uses stricter headroom ceilings: acquisition max at most 250 ms and completion-gap max at most
400 ms. Those bounds leave at least 250 ms of acquisition margin and one complete 100 ms nominal sampling interval of
completion-gap margin. A run between a decision ceiling and the hard gate can remain an operationally successful smoke
result, but it cannot authorize the next immutable production attempt. A shorter `--duration-seconds` run is useful only
as a smoke test.

Decision-grade soak evidence is also bound to the exact clean commit and tree within a trusted-quiescent-worktree
boundary. After initialization, the launcher reads canonical source files through no-follow descriptors bound to their
observed path identities, compares those observed bytes with their `HEAD` blobs, monitors source-file and parent-directory
identities throughout the run, and checks them again at completion. The inventory includes the shared launcher, import
guard, soak implementation, every importable NERB Python source, native build inputs, and active reader lock. Both isolated
workers must attest the same observed worktree source and bootstrap identities. The aggregate policy records this boundary
as `trusted_quiescent_worktree_observation`; it does not claim that a process can retrospectively prove the bytes Python
compiled before the first source snapshot.

A `decision_grade: true` result is valid only when the operator uses a dedicated, clean, access-controlled checkout and
keeps its source tree and Git metadata quiescent from interpreter startup through command completion. Editors, Git
commands, checkout automation, and other writers must not mutate that checkout during the command. A same-UID or root
actor that can swap and restore files between observations or modify the running process is outside this threat model. If
that assumption cannot be guaranteed, the aggregate may still diagnose the observer but must not authorize a production
attempt. The shared launcher installs a fresh owner-only bytecode root before loading any project or dependency code,
disables site processing and hooks, and validates the exact worktree source and virtual-environment dependency roots.
Invoking the soak script directly remains useful for smoke investigation but is categorically ineligible for
`decision_grade: true`.

A dirty, changed, differently imported, or mismatched source tree can still support a local smoke investigation but cannot
produce decision-grade evidence. The aggregate report also attests the interpreter major/minor, installed PyArrow version,
path-free distribution inventory hash, exact imported module origins, and current reader-lock hash without exposing
interpreter, package, or module paths. Decision-grade evidence requires exactly Python 3.13 and PyArrow 25.0.0; the
imported `pyarrow`, `pyarrow.compute`, and `pyarrow.ipc` modules must be the exact files listed by that distribution under
the validated locked virtual-environment root; and the hash of the current `pyproject.toml` plus `uv.lock` reader lock must
match the hash of those files at `HEAD`. Use the locked sync above before the exact `--no-sync` invocation; an environment,
bootstrap, provenance, or reader-lock mismatch remains an explicitly limited smoke result and cannot authorize the next
immutable production attempt.

The full run has one cleanup owner for its complete lifetime. Preparation, split, and bank-build transactions transfer
their retained payload descriptors to that outer transaction before their own commit handles close. After every phase
stops its writers, the outer transaction also performs a bounded no-follow adoption pass over every regular file created
directly by the reader or another third-party component. Cleanup authority remains live through post-promotion gates and
durable attempt terminalization, so an in-process later failure wipes authenticated payload inodes even if a same-user
race moved a child outside the staging tree. Before promotion, the attempt ledger durably binds the complete inode
inventory. Phase adoption and every later cleanup operation share one stage-rooted envelope of 1,000,000 directory entries
and 64 levels. The whole-stage pre-promotion walk is the aggregate gate across all phase roots and reserves the final
`COMMITTED` entry; a phase-local walk cannot make a larger aggregate tree promotable. Crash recovery wipes every reachable
expected inode that it can authenticate through a no-follow descriptor. Linux can recover an owner-inaccessible durably
bound output parent or output/tombstone child with `O_PATH`, verify its recorded device/inode identity, repair that inode to
mode `0700` through the descriptor, and reopen or retain the same inode for wiping. Readable bound parents are likewise
restored through their verified descriptor. After every process holding the directory has terminated, unprivileged macOS
has no equivalent identity-bound permission-repair primitive; if either the bound parent or child is inaccessible,
recovery fails without applying a name-based chmod or touching a possible substitute and cannot claim that sensitive
content was wiped. A failed authenticated wipe is moved
to the bounded process retry registry and blocks terminalization until verified zero; a later in-process recovery retries
that authority before writing a receipt. Recovery reports `sensitive_content_wiped: false` when inventory or path evidence
is incomplete. It also reports `false` whenever recovery retains a writable tombstone: the verified empty state cannot
be held through the separate durable receipt commit, so recovery does not turn that transient observation into positive
wipe evidence. Ordinary in-process cleanup applies the same rule, and the receipt writer independently rejects positive
wipe evidence whenever a retained tombstone remains. `false` means that durable positive wipe evidence is unavailable;
it does not assert that sensitive bytes are known to remain. Cleanup fields on failed or interrupted attempts are
operational records rather than decision-authoritative privacy evidence. The portable artifact preserves their exact
hash-chain bytes while explicitly listing failed-attempt cleanup and durable wipe state as not independently attested.
Recovery does not claim that an inode moved before a new process opened it can be recovered without a
live descriptor. The process-wide limit is 128 retained files. Under `RLIMIT_NOFILE`, NERB also reserves the maximum
64-level cleanup walk plus 8 descriptors for file and transaction overhead (72 total). Exceeding the 128-file cap or the
aggregate 1,000,000-entry/64-level tree envelope fails closed before promotion.

`verify-portable-enron-capacity --artifact capacity-decision.json` is a clean-clone verifier. It checks closed report
arithmetic, the full attempt hash chain, terminal cross-bindings, the measured Git commit and root tree, tracked source
blobs, reader lock, and native build-source commitment. It does not independently re-read the original private payload,
re-attest the promoted inode, prove recorded timing/RSS/disk observations, or reproduce/authenticate the native binary
bytes. It also does not independently byte-attest HTTP dependencies below the five critical reader distributions.
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

# Enron Benchmark v2 Charter

> **Status: executable contract frozen; benchmark execution staged.** The v2 manifest/evidence schemas and semantic
> verifier are implemented. The preparation pipeline, evaluator, bank, and real-corpus evidence will land in later work.
> The existing `scripts/enron_bank_build_benchmark.py`, its `nerb.enron_benchmark.v1` output, the v1 autoresearch
> harness, committed hero measurements, and previously published Enron numbers are historical. They do **not** satisfy
> this charter and must not support a public quality, privacy, performance, or product claim.

NERB's Enron benchmark demonstrates a privacy-first intelligence-cache workflow: a capable agent turns a large private
organizational source into a reviewed entity bank once; an application compiles that bank once and reuses it for fast,
deterministic scans. The benchmark must show both sides of that proposition without conflating them:

1. how much sensitive information the construction process learned; and
2. whether NERB reliably and efficiently recognizes the approved knowledge it was given.

Preventing sensitive-data leakage is the primary user outcome. Speed, memory, false alarms, and over-redaction remain
important constraints, but an aggregate F1 score or a fast scan cannot compensate for unexplained misses.

## User Workflow

The v2 demonstration models the following production workflow:

1. A user authorizes a specific source, revision, purpose, taxonomy, and retention policy.
2. Private preparation profiles and cleans the source, assigns stable document identities, builds duplicate/thread leakage
   groups, and freezes train, validation, and sealed-test manifests.
3. An agent uses **train only** to mine candidates. A reviewer promotes well-supported aliases and generic structured-PII
   patterns; ambiguous candidates stay draft or inactive.
4. Synthetic conformance cases validate every approved active pattern, including its case, normalization, boundary,
   overlap, and canonical-identity semantics.
5. Validation evidence tunes construction rules and explicit privacy/utility thresholds. Validation text may inform the
   algorithm and thresholds, but its labels or literal surfaces may not be copied into the bank as a shortcut.
6. The bank, evaluator, thresholds, and performance workloads are frozen and hashed.
7. The application compiles the bank once, then scans many documents through the direct reusable `Bank` path. One-time
   profiling, build, curation, and compile costs are reported separately from repeated scan cost.
8. A release steward runs the sealed final test once. A privacy-safe verifier checks provenance, arithmetic, gates, and
   claim consistency before aggregate evidence is published.

This is an intelligence-cache demonstration, not a claim that Enron represents every organization or that a bank built
for one organization transfers unchanged to another.

## Privacy Threat Model

The protected subject is a person or organization represented in authorized plaintext by a sensitive span: for example a
person name, email address, phone number, account identifier, or another class approved by the benchmark taxonomy. The
principal failure is residual sensitive text after a workflow relied on NERB to find or redact it. One miss can matter,
so the headline evidence includes missed spans and documents containing any miss rather than F1 alone.

In scope are failures caused by:

- an identity or alias absent from the catalog;
- an approved pattern not matching under its declared normalization and boundary semantics;
- a match mapped to the wrong canonical identity;
- cleaning, MIME/HTML handling, Unicode, malformed input, overlap resolution, or document-size behavior;
- overbroad patterns that create false alarms or remove excessive non-sensitive text; and
- performance or memory behavior that makes compile-once/scan-many use impractical at realistic bank sizes.

The primary scan text is the cleaned message content that a user would actually process. The evaluator must never append
`From`, `To`, `Addresses`, labels, candidate inventories, or other answer-bearing fields to that text. Structured fields
may provide separately labeled weak-supervision evidence, but not an injected primary test view.

Out of scope unless a later version names and measures them are encrypted content, undecoded attachments, OCR, images,
audio, meaning that is identifiable only from broad context, deliberate bank theft, and cryptographic anonymity. NERB
pseudonymization is deterministic replacement, not proof of anonymization. The bank and reversible replacement data are
themselves sensitive assets.

## Guarantee Boundary

NERB can make a narrow deterministic guarantee:

> Given the same validated bank, engine identity, scan options, and input bytes, an approved active pattern is detected
> and mapped according to its declared normalization, regex, boundary, priority, and overlap semantics when the input
> contains a qualifying occurrence.

V2 promotion requires 100% synthetic catalog conformance and zero wrong canonical mappings for those approved cases.
Natural-text cataloged spans provide a second check that preparation and scanning preserve that behavior.

The guarantee does not cover an unknown name or free-form identifier merely because it is PII. Detection of unknown PII
depends on catalog coverage and any separately evaluated generic fallback patterns. Open-world recall must therefore be
measured and reported; it must never be described as guaranteed 100% recall. A deterministic miss is still a miss.

The public-verifier guarantee is narrower still. Content hashes, frozen descriptors, and privacy-safe inventories prove
immutable commitments and let the verifier recompute arithmetic and claim support. They do not prove that an honest
runner actually derived an inventory from the addressed private input or ran the declared bank against those bytes.
Authorized harness execution, retained private audit material, and independent review provide that evidence. A clean
clone can verify schema conformance, hashes, aggregate arithmetic, gates, lineage, and claims without private text.

## Taxonomy And Bank Policy

Taxonomy follows the privacy workflow and corpus evidence rather than a universal NER label set. The initial v2 bank is
expected to consider high-confidence people and contact aliases, organizations and domains, and defensible generic
structured-PII fallbacks. Additional classes require a written threat rationale and appropriate labels. A class without
credible quality evidence may remain exploratory but cannot contribute to a promoted headline claim.

Every promoted name or pattern must retain inspectable, privacy-safe metadata or a private reference for:

- privacy class and canonical identity;
- source/provenance hash and construction policy version;
- observation count and first/last-seen interval;
- confidence and label strength;
- ambiguity/collision analysis and curation rationale; and
- active, draft, or inactive status.

Stable aliases should normally be literals. Regexes are appropriate for genuinely structured forms, not for hiding an
unreviewed inventory. A collision that cannot be mapped unambiguously must be resolved by context-independent policy or
kept inactive. Test observations never become candidates for the same benchmark version.

## Evidence Strength

Every quality slice carries exactly one `label_strength` for provenance and separately declares:

- `annotation_scope`: the entity classes, span rules, included document regions, and exclusions the annotator attempted to
  cover; and
- `annotation_completeness`: exactly one of `exhaustive_within_scope`, `partial`, or `not_applicable`.

Completeness is always relative to the declared scope; an `independent` label is not automatically exhaustive. Counts
from different strengths, scopes, or completeness states stay separate.

| Label strength | Meaning | Permitted use |
| --- | --- | --- |
| `independent` | Human or externally published annotations produced independently of the candidate bank and its output. Annotation scope and known omissions are recorded. | Final open-world quality only when `annotation_completeness` is `exhaustive_within_scope`; otherwise explicitly partial labeled-span diagnostics. |
| `structured_weak` | Labels derived from source fields or deterministic rules, such as parsed sender/recipient addresses. They may be accurate but are not independent of source structure or heuristics. | Coverage and class diagnostics, candidate discovery on train, and explicitly weak validation/test slices. Never relabeled as independent recall. |
| `synthetic_conformance` | Positive, negative, boundary, normalization, overlap, and adversarial cases derived from the frozen active bank contract. | Catalog conformance and canonical-mapping guarantees. Not catalog coverage or open-world recall. |
| `unlabeled` | Text with no exhaustive gold spans. Absence of a label is not evidence that a prediction is wrong. | Throughput, memory, robustness, and qualitative inspection only; no precision, recall, or F1. |

The manifest binds exact document and span populations for each role covered by a label artifact. Every natural-text
`independent` or `structured_weak` artifact covers one entity class so those populations cannot be hidden in a vague
multi-class total. Annotation provenance records the protocol and producer, reviewer, review status, and adjudication
artifact. `independent` and `synthetic_conformance` labels require a distinct reviewer and content-addressed
adjudication evidence; declaring a label independently reviewed is not enough by itself.

Only an `independent`, `exhaustive_within_scope` slice may support open-world PII recall, precision/F1, negative-document
false-alarm rate, leaked-sensitive-character measures, or over-redaction measures. A `partial` independent slice may
report raw labeled-span hits and misses as a partial diagnostic, but those values are not open-world recall and
predictions outside its labels are not false positives. `structured_weak` and `synthetic_conformance` slices keep their
limited uses even if their own declared scope is exhaustive. `unlabeled` slices use `not_applicable` completeness.

Independent person-name evidence may use the published
[CMU Enron Meetings XML archive](https://www.cs.cmu.edu/~einat/EnronMeetings-XML.zip), pinned by SHA-256
`e7d8dbd9e066eddd6d706a041e379ca93daf9e441a73009646ead41e94a60202`. Its published split and annotation scope must be
preserved and reported; its labels do not prove quality for email addresses, domains, or other classes. The large email
source remains [`corbt/enron-emails`](https://huggingface.co/datasets/corbt/enron-emails) at revision
`cfc06c758093d90993abce1a43668fb7357258a6` unless a future benchmark version deliberately changes it. Source identity
alone is not sufficient: downloaded content hashes are mandatory.

## Sealed Train, Validation, And Test Policy

V2 uses three immutable roles, created before candidate tuning:

- **Train:** available for profiling, candidate mining, bank construction, and curation.
- **Validation:** available for error analysis and tuning construction policy, thresholds, and generic fallbacks. It is not
  a literal alias feed.
- **Final test:** content, labels, and per-document outputs remain sealed from builders and autoresearch until the bank,
  evaluator, thresholds, claims, and workload hashes are frozen.

Split assignment is row-order independent and operates on leakage groups rather than individual rows. A group joins exact
duplicates, normalized near duplicates, reply/forward/thread relatives, and other answer-sharing records identified by
the frozen preparation policy. No group may cross roles. The manifest records group-policy digest, split seed, artifact
hashes, row and group counts, cross-split audit results, and explicit temporal/future, seen-identity, unseen-identity,
head/tail, and challenge cohorts where labels support them.

Builders and autoresearch may read train and validation artifacts only. They may not read the final-test text, labels,
per-document metrics, failure examples, or a scalar derived from final-test quality. The final test is run once for the
frozen release candidate; it is never an optimization objective. Every access and its privacy-safe aggregate outcome,
including a failed or aborted run, enters an append-only public benchmark lineage. A failure may be followed by a new
benchmark version and newly sealed test, but the successor must link the failed version and disclose the changes and
decisions informed by its outcome; it never replaces or hides that result. Repeatedly tuning against the same final test
or selectively surfacing only successful benchmark versions invalidates promotion.

Before access, the manifest designates exactly one prepared primary natural-content view and binds its artifact and
content policy. A promoted quality run must attest that this view contains no answer-bearing fields. The manifest also
freezes each quality slice's label artifact, role, class, cohort, text view, gate status, and exact document, span,
cataloged-span, sensitive-positive, catalog-positive, negative-document, sensitive-character, and evaluated-character
denominators. Evidence must preserve the plan's order and membership; each gate slice is the complete independently and
exhaustively labeled final-test role, not a favorable subsample. Its annotation regions must equal the complete primary
view, and its annotation scope cannot exclude any part of that view.

The conformance plan separately freezes content-addressed positive and negative/adversarial case artifacts, their
counts, the exhaustive synthetic label artifact, and the conformance policy hash. It requires positive support for every
active pattern. The final-test frozen target and every lineage entry bind the manifest hash alongside the bank,
evaluator, split, thresholds, performance plan, source commit, and freeze time.

## Quality Metrics

Metrics are computed per label-strength, entity-class, and cohort slice before any permitted aggregate. Exact-span
matching is one-to-one and includes the declared entity class. Canonical identity correctness is measured separately.
Let:

- `D` be the evaluated document IDs and `Omega = {(d, i) | d in D and i is a Unicode scalar index in d}` be the
  document-disjoint universe of evaluated character positions;
- `G` be eligible gold sensitive spans in a slice;
- `K` be spans in `G` whose actual occurrence qualifies under an approved active catalog pattern, determined without
  looking at scan output;
- `P` be predicted sensitive spans; and
- `TP`, `FP`, and `FN` use deterministic one-to-one exact-span/class matching;
- `U_G` be the subset of `Omega` covered by gold-sensitive spans; and
- `U_P` be the subset of `Omega` covered by predictions that the declared redaction policy would remove.

Empty denominators produce `not_evaluated`, never `0`, `1`, or a passing gate.

### Coverage, Conformance, And Recall

These terms are not interchangeable:

- **Catalog coverage** is `|K| / |G|`. It asks how much labeled future sensitive text was knowable from the active bank,
  independent of whether the engine found it.
- **Natural-text cataloged PII recall** is `cataloged_TP / |K|`. Its complement is the count of **missed cataloged
  sensitive spans**. A cataloged match mapped to the wrong identity is not a correct cataloged true positive.
- **Catalog conformance** is `correctly_detected_and_mapped_approved_cases / all_approved_positive_cases` on exhaustive
  synthetic conformance cases. Negative/adversarial cases are reported alongside it. Promotion requires `1.0` recall and
  zero wrong canonical mappings.
- **Open-world PII recall** is `TP / (TP + FN)` over all eligible independently labeled PII in scope, whether cataloged,
  matched by a generic fallback, or unknown. This is the relevant total-leakage measure and is not guaranteed by the
  catalog.

For example, suppose independent labels contain 100 sensitive spans and 80 qualify as cataloged. Catalog coverage is
80%. If NERB correctly finds and maps all 80 but has no fallback discoveries, catalog conformance and natural cataloged
recall can both be 100% while open-world recall is only 80%. If it finds only 79, catalog coverage remains 80%, natural
cataloged recall is 98.75%, and the run has one cataloged miss. No one of these numbers substitutes for another.

### Privacy And Utility Measures

Every promoted quality slice reports raw integer counts as well as derived values:

| Measure | Definition |
| --- | --- |
| Missed sensitive spans | `FN`; shown for all eligible gold and separately for cataloged spans. Lower is better. |
| Cataloged PII recall | `cataloged_TP / |K|`; accompanied by wrong-mapping count. Higher is better. |
| Documents with any open-world miss (document leak rate) | Positive documents containing at least one `FN` divided by documents containing at least one eligible gold span. Report count and rate. Lower is better. |
| Documents with any cataloged miss | Number and rate of catalog-positive documents containing at least one missed or wrongly mapped cataloged span. Denominator: documents containing at least one cataloged gold span. |
| Leaked sensitive characters | `|U_G − U_P|`; report the count, rate over `|U_G|`, and documents with any uncovered sensitive character. This distinguishes residual text from an exact-span miss covered by a wider safe redaction. |
| Sensitive-character recall | `|U_G ∩ U_P| / |U_G|`. Higher is better. It supplements rather than replaces exact-span/class recall and canonical-mapping checks. |
| Open-world PII recall | `TP / (TP + FN)` on `independent`, `exhaustive_within_scope` labels. Higher is better. |
| Catalog coverage | `|K| / |G|`, independent of predictions. Higher is better but is not matcher quality. |
| Wrong canonical mappings | Correct-span cataloged predictions assigned to the wrong canonical identity. Promotion target: zero. |
| Negative-document false-alarm rate | Negative documents with at least one prediction divided by exhaustively labeled negative documents. Lower is better. |
| Precision | `TP / (TP + FP)`. Predictions in partially labeled or unlabeled text cannot be used as false positives. |
| F1 | Harmonic mean of precision and recall. Secondary summary only; it cannot hide misses. |
| Over-redacted characters | `|U_P − U_G|`; report the count and divide by `|Omega|` for the rate. Positions are `(document_id, scalar_index)` pairs and overlaps within one document count once. |

The evidence also reports total positive/negative documents, gold/predicted spans, total evaluated characters, and the
numerators and denominators for every rate. Per-class, head/tail, seen/unseen identity, temporal/future, document-size,
hit-density, and challenge slices are required when applicable. Micro averages never replace these slices.

V2 does not assert a binomial confidence interval for quality. The sealed benchmark is a fixed finite evaluation, and
the contract makes no independent-and-identically-distributed sampling claim that would justify one. This does not
excuse small evidence: raw support counts and promotion support floors are mandatory and stay visible beside every rate.

## Performance And Scale Protocol

The primary runtime measurement is the direct compiled-bank reuse path: construct one validated `Bank`, warm it under a
declared policy, and call the same bank repeatedly. The following are separately named measurements and must not be
combined into a single latency number:

- one-time source profiling/build/curation;
- cold validation and native compile in a fresh process;
- helper/source-cache miss and helper/source-cache hit;
- direct warm scan/project time;
- input decode/read and any redaction/serialization post-processing; and
- end-to-end application time.

Every workload declares one timing unit. `operation` measures a bank setup operation and has no document-throughput
denominator. `document` measures document-level latency. `whole_input` measures a complete bound input and supports
documents/second, MiB/second, and records/second. Setup phases cannot borrow an input denominator; every scan-bearing
phase binds the exact bank and input descriptor. Every workload also binds a frozen harness descriptor containing its
declared command, harness-source digest, operation-specification digest, and phase. Profiling and source-build harnesses
bind the declared corpus content and frozen train-split artifact, respectively. Workload hashes freeze that harness plus
the phase, bank/input identities, unit, warmups, work per sample, concurrency, process model, and statistic methods
without hashing observed timings into the plan.

Each real or generated input descriptor binds a content-addressed artifact and a bank-specific, content-addressed
privacy-safe inventory containing only byte and detected-record counts per document. The verifier recomputes the
document, byte, and record totals, length and hit distributions, and deterministic size and density cohorts from that
inventory; promoted decision cells must provide it. This commits every throughput denominator without publishing
message text.

Bank descriptors freeze taxonomy composition as well as entity, name, alias, literal-pattern, regex-pattern, and byte
counts. Promotion exercises distinct 1k, 10k, 25k, and 100k active-alias banks whose taxonomy and alias/regex
proportions track the evaluated bank within the contract tolerance. These are controlled measurements, not four
unrelated cells: every scale uses the same canonical negative, medium, serial whole-input shape; density varies on a
fixed bank, size, and synthetic generator family; size varies on a fixed bank, density, and synthetic generator family;
and serial/concurrent cells use the exact same bank, input, sample unit, and work. Unrelated real inputs cannot stand in
for controlled generated sweeps. Direct-scan inputs cover negative, sparse, normal, and dense hits; small, medium, large,
and huge documents; and both serial and machine-bounded concurrent execution.

Each lifecycle phase—source profile, source build, cold compile, helper cache miss, helper cache hit, direct bank scan,
and end to end—has an evaluated-bank decision cell. Decision-grade cells use one work unit and at least 100 raw timing
samples (inline or by verified content-addressed reference), plus one positive RSS sample per timing sample with peak RSS
equal to their maximum. Fresh-process phases use zero warmups; reused-process phases use at least three. Median and
median absolute deviation use the declared conventional methods; nearest-rank p95 requires 20 samples and p99 requires
100.

Every decision cell has same-machine comparisons against an exact semantic baseline on an identical operation
specification, source artifact, phase, bank, input, warmup policy, sample count, sample unit, work, and concurrency. At
minimum it compares p99, plus MiB/second for whole-input cells, and promotion rejects a regression beyond the frozen
noise multiplier and tolerance. Comparison hashes commit only the candidate and baseline cell IDs, metric, direction,
and noise policy, not observed values or outcomes. Capability differences must still be stated for non-equivalent
exploratory baseline measurements, which are not exact regression comparisons.

Absolute results are hardware-specific. Promotion uses thresholds frozen from validation and a same-machine repeated
baseline, reports noise diagnostics, and fails closed when required samples, input inventories, RSS, or environment
provenance are missing. Every decision cell gates median, p95, p99, and peak RSS; document cells also gate seconds per
document, while whole-input cells gate documents/second and MiB/second. Validation may tighten but cannot weaken the
deliberately conservative evaluated-bank headline policies: document p99 at most 50 ms, whole-input throughput at least
100 documents/second and 1 MiB/second, and peak RSS at most 8 GiB. These absolute bounds prevent a similarly slow
baseline from making an impractical candidate promotable. CI smoke timing is robustness evidence, not a substitute for
the decision-grade protocol.

The value demonstration records an additive parameterized break-even model rather than inventing hosted-model prices.
Candidate fixed costs separate declared source curation, measured source profiling, measured bank build, and measured
cold compile; marginal scan cost comes from the promoted real-input document-latency workload and is paired with its
comparable exact-baseline scan. Every measured component uses the unique evaluated bank, never a convenient synthetic
scale bank. Other fixed or marginal assumptions remain explicit. Let `P` be profiling, `B` be private curation/build
cost, `C` cold compile cost, `S(n)` repeated NERB scan cost for `n` documents, and `A(n)` the alternative's additive cost.
Report the smallest `n` for which `P + B + C + S(n) <= A(n)`. The value-plan hash commits component roles and sources,
units, range, and declared assumption values, but not later measured workload values or the derived result. Promotion
requires a finite supported advantage or break-even. This model supplements privacy/quality gates; it never discounts a
miss.

## V2 Artifact Contract

V2 has two versioned JSON contracts:

- `nerb.enron_manifest.v2` binds evaluator ID/digest; source ID, revision, and content hashes;
  cleaning/group/split policy hashes; the split-manifest hash; train/validation/test artifact hashes and counts; the
  primary prepared text view; bank hash; exact per-role label populations and annotation provenance; quality-denominator
  and positive/negative conformance plans; package, native-engine, commit, and schema identities; exact commands;
  environment; and privacy-safe validation status.
- `nerb.enron_evidence.v2` binds one manifest hash to evaluation status, aggregate quality slices, catalog-conformance
  results, the final-test frozen target and lineage, performance banks and inputs, raw timing samples or references plus
  raw RSS samples, frozen command/spec/source-bound performance harnesses, exact baseline comparisons and additive value
  models, configured thresholds, promotion-gate results, verifier status, and supportable claims.

Paths and commands are sanitized but remain exact enough to reproduce in an authorized environment. Private artifact
references use stable logical IDs and hashes, not workstation paths. Hash algorithms and canonicalization rules are part
of the schema contract. Missing evaluator, source, split, bank, package/engine/commit, command, or environment provenance
is an error.

Quality is explicitly `evaluated` or `not_evaluated`. Missing slices, zero eligible gold, absent independent labels, and
empty conformance cases cannot silently become zero-filled success. Non-finite numbers are invalid. A verifier recomputes
all possible rates from integer counts, checks totals and slice identities, checks manifest/evidence hashes and version
freshness, validates gate implications, and rejects any claim whose scope or label strength exceeds its evidence. This
lets a clean clone verify arithmetic and claim consistency without access to private email text.

The schema and synthetic fixtures are part of the v2 contract, but a schema-valid fixture is not real-corpus evidence.
No v2 command or real artifact is claimed on this page until later implementation issues deliver and verify it.

## Promotion Gates

A result is promotable only when all applicable checks pass:

1. provenance is complete; hashes, evaluator digest, split leakage audit, bank/runtime identities, and command/environment
   records validate;
2. quality evidence is present, non-empty, arithmetically consistent, and separated by label strength;
3. all approved active patterns have non-empty synthetic coverage, 100% catalog conformance recall, zero wrong canonical
   mappings, and zero unexpected matches on required synthetic negative/adversarial cases;
4. natural cataloged misses and documents with any cataloged miss are zero in every gate-designated slice;
5. minimum open-world span and sensitive-character recall, maximum document and sensitive-character leak rates, maximum
   negative-document false-alarm rate, maximum over-redaction rate, and any per-class floors were frozen from validation
   before final-test access and pass on the one-shot final evidence;
6. required performance workloads satisfy predeclared latency, throughput, memory, and regression thresholds with valid
   raw samples and matching fingerprints, and the evaluated-bank headline thresholds meet the conservative absolute
   latency, throughput, and memory policies;
7. privacy-safe serialization/scan passes and no raw text, aliases, addresses, per-document failures, or sensitive paths
   appear in public artifacts; and
8. an independent reviewer verifies the evidence/claim mapping at the final commit.

Every promotion-gate quality slice must contain at least 100 documents, 100 gold spans, 20 negative documents, and 500
sensitive-gold characters. Validation may tighten, but cannot weaken, the v2 policy floors: open-world recall at least
0.95, catalog coverage at least 0.80, cataloged recall exactly 1.0, and sensitive-character recall at least 0.98. The
corresponding ceilings are document leak rate 0.05, sensitive-character leak rate 0.02, negative-document false-alarm
rate 0.50, and over-redaction rate 0.05. Zero cataloged misses, wrong canonical mappings, and catalog-miss documents are
separate exact gates.

Structured public claims are not selected from convenient diagnostics. Promotion requires the full quality metric set
for every gate-designated slice, a passing catalog-conformance claim, and performance claims tied to the exact promoted
document-latency and whole-input-throughput workloads. Each claim repeats its exact slice or workload, scope, label
strength/completeness, bank, evaluator, source revision, benchmark version, and environment provenance.

A failed final gate is evidence, not permission to tune on the test. Claims must name the corpus revision, benchmark
version, bank and evaluator hashes, label strength, class/cohort scope, and machine context for performance. “No known
cataloged miss in this frozen evaluation” is supportable when true; “NERB catches all PII” is not.

Failed or aborted aggregate outcomes remain publishable in the append-only lineage when promotion and verifier success
are false. Recording a failure is mandatory evidence; it is never itself a passing claim.

## Artifact Retention And Ethics

Enron data contains real communications and personal information. Historical public availability does not imply consent
to republish, contact, rank, or profile people. The benchmark is for aggregate software evaluation only. Known annotation
gaps, historical-domain bias, source integrity limitations, access terms, and intended use must be recorded with every
manifest.

Raw downloads, cleaned text, annotations, split files, real banks, aliases, match records, failure examples, and
autoresearch logs stay under ignored `.nerb/` paths or an equivalently access-controlled store. Encrypt them at rest where
practical, grant least-privilege access, and record an owner, purpose, creation time, retention deadline, and deletion
outcome. A production user's operational bank may have its own approved lifecycle; benchmark copies do not inherit
indefinite retention.

Git may contain only schemas, synthetic fixtures, source/policy hashes, aggregate evidence, and sanitized examples that
pass automated privacy checks. Public evidence must omit raw strings, context snippets, addresses, names, local paths,
and small slices that enable reconstruction. The public-contract scan deliberately rejects any at-sign, common SSN or
phone shape, and punctuation-wrapped local path; diagnostics are deterministic and bounded without echoing rejected
values. This includes compatibility-normalized/fullwidth identifier forms, canonical E.164 numbers, common Unicode
separators and decimal digits, formatted international numbers, compatibility-normalized path punctuation, UNC shares,
and local paths attached to command options. HTTP(S) remote paths, nested remote links, and promotion-gate JSON pointers
remain permitted, but recursively partitioned and repeatedly decoded URL payloads cannot smuggle an identifier, local
path, or file URI. External sample and inventory resolvers and trusted-lineage prefixes must use bounded exact JSON-like
built-in containers and scalar types. Charts are regenerated solely from the verified aggregate evidence bundle.

## Historical V1 Quarantine

V1 is useful as a record of what needed improvement, not as a baseline claim. Its two-way split fed held-out F1 back into
autoresearch; evaluated text included injected address inventory; regex/structured derivations were treated as gold;
catalog coverage was described as recall; public arithmetic drifted from stored counts; and public evidence was tied to
stale runtime identities.

| Historical validity problem | V2 control |
| --- | --- |
| Test score used for optimization | Train/validation-only tuning and one-shot sealed final test |
| Answer-bearing address inventory in scan text | User-visible cleaned content is the only primary scan view |
| Regex/structured labels presented as independent gold | Required `label_strength` and non-combinable evidence slices |
| Catalog coverage called recall | Separate formulas and raw counts for coverage, conformance, cataloged recall, and open-world recall |
| Two-way row split and duplicate/thread leakage risk | Immutable group-aware three-way split plus cross-split audit |
| F1-first promotion | Miss counts, document leak rate, open-world recall, and catalog guarantees lead |
| Stale runtime metadata and arithmetic drift | Versioned identities, integer numerators/denominators, and independent verification |
| Public artifacts containing aggregate v1 numbers | Explicit historical label; no promotion until verified v2 evidence exists |

Do not rerun the v1 command and relabel its output v2. Do not use its historical benchmark JSON, generated images, or
autoresearch rows to claim current Enron quality or performance. Later v2 implementation must produce new artifacts under
the contracts above.

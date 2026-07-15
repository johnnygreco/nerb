# Enron Benchmark Charter

> **Status: known-bank contract evidence passed; standalone-redaction bank gate failed.**
> The full pinned-source preparation, immutable split, train-only bank build, capacity proof, decision-grade performance
> run, one-shot 100-document sealed gold audit, prediction audit, and aggregate publication are complete. NERB correctly
> mapped 39,604/39,604 approved pattern cases; the constructed bank covered only 146/1,393 independent gold spans and
> must not be used alone as a comprehensive PII redactor. See the [verified aggregate evidence](enron-evidence.md).

NERB's Enron benchmark demonstrates a known-entity intelligence-cache workflow: a capable agent turns a large
organizational source into a reviewed entity bank once; an application compiles that bank once and reuses it for fast,
deterministic scans. The benchmark keeps four questions separate:

1. whether NERB honors every approved pattern and canonical mapping in the supplied bank;
2. whether stricter exact-span evaluation agrees on catalog-qualified natural occurrences;
3. how much of a target population the construction process put into the bank; and
4. whether compile-once/scan-many is fast and resource-bounded at realistic scale.

The first question is NERB's core product contract. Population coverage and open-world recall matter when an application
claims that a particular bank can discover or redact arbitrary PII; those application metrics must never be presented as
known-bank matcher recall. Speed, memory, false alarms, and over-redaction remain separately measured constraints.

## User Workflow

The demonstration models the following production workflow:

1. A user authorizes a specific source, revision, purpose, taxonomy, and retention policy.
2. Private preparation profiles and cleans the source and assigns stable document identities and grouping features; the
   immutable [split workflow](enron-splits.md) builds leakage components and freezes train, validation, and sealed-test
   bundles.
3. An agent uses **train only** to mine candidates. The implemented [bank workflow](enron-bank-building.md) promotes
   well-supported aliases and a bounded email fallback; ambiguous candidates stay draft or rejected.
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

## Standalone Privacy-Redaction Threat Model

The benchmark deliberately includes an application-specific test beyond NERB's guarantee: whether the constructed bank
can stand alone as a comprehensive privacy redactor. In that threat model, the protected subject is a person or
organization represented in authorized plaintext by an in-scope sensitive span. The principal application failure is
residual sensitive text after a workflow relied on that bank to find every occurrence. One miss can matter, so this
separate assessment includes missed spans and documents containing any miss rather than F1 alone.

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

Known-bank contract evidence requires 100% synthetic catalog conformance and zero wrong canonical mappings for those
approved cases. Natural-text cataloged spans provide a separate, stricter exact-span diagnostic.

The guarantee does not cover an unknown name or free-form identifier merely because it is PII. Detection of unknown PII
depends on catalog coverage and any separately evaluated generic fallback patterns. When a bank is proposed for
open-ended discovery or comprehensive redaction, open-world recall must be measured and reported as bank/application
coverage. It must never be described as NERB matcher recall or as guaranteed 100% recall.

The public-verifier guarantee is narrower still. Content hashes, frozen descriptors, and privacy-safe inventories prove
immutable commitments and let the verifier recompute arithmetic and claim support. They do not prove that an honest
runner actually derived an inventory from the addressed private input or ran the declared bank against those bytes.
Authorized harness execution, retained private audit material, and independent review provide that evidence. A clean
clone can verify schema conformance, hashes, aggregate arithmetic, gates, lineage, and claims without private text.

## Taxonomy And Bank Policy

Taxonomy follows the privacy workflow and corpus evidence rather than a universal NER label set. The initial bank is
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
kept inactive. Test observations never become candidates for the evaluated release candidate.

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

The manifest binds exact document and span populations for each role covered by a label artifact. The promoted Enron
panel has one combined `person_contact` artifact and gate so document and character unions are measured once across the
active privacy scope. Separate person and contact artifacts and diagnostic slices expose each class's support; neither
class can be hidden in the combined total. Annotation provenance records the protocol and producer, reviewer, review
status, and adjudication artifact. `independent` and `synthetic_conformance` labels require a distinct reviewer and
content-addressed adjudication evidence; declaring a label independently reviewed is not enough by itself.

Only an `independent`, `exhaustive_within_scope` slice may support open-world PII recall, precision/F1, negative-document
false-alarm rate, leaked-sensitive-character measures, or over-redaction measures. A `partial` independent slice may
report raw labeled-span hits and misses as a partial diagnostic, but those values are not open-world recall and
predictions outside its labels are not false positives. `structured_weak` and `synthetic_conformance` slices keep their
limited uses even if their own declared scope is exhaustive. `unlabeled` slices use `not_applicable` completeness.

Independent person-name evidence may use the published
[CMU Enron Meetings XML archive](https://www.cs.cmu.edu/~einat/EnronMeetings-XML.zip), pinned by SHA-256
`e7d8dbd9e066eddd6d706a041e379ca93daf9e441a73009646ead41e94a60202`. Its published split and annotation scope must be
preserved and reported; its labels do not prove quality for email addresses, domains, or other classes. The large email
source is [`corbt/enron-emails`](https://huggingface.co/datasets/corbt/enron-emails) at revision
`cfc06c758093d90993abce1a43668fb7357258a6`. Changing that pin creates a distinct source lineage and requires a new
preregistered run. Source identity alone is not sufficient: downloaded content hashes are mandatory.

## Sealed Train, Validation, And Test Policy

The implemented commands, private-bundle boundary, exact/reference/thread/near-duplicate component policy, temporal
assignment, diagnostic sampling, support floors, and one-shot access behavior are documented in the
[immutable split guide](enron-splits.md).

The benchmark uses three immutable roles, created before candidate tuning:

- **Train:** available for profiling, candidate mining, bank construction, and curation.
- **Validation:** available for error analysis and tuning construction policy, thresholds, and generic fallbacks. It is not
  a literal alias feed.
- **Final test:** content, labels, and per-document outputs remain sealed from bank-building and policy-tuning processes
  until the bank, evaluator, thresholds, claims, and workload hashes are frozen.

Split assignment is row-order independent and operates on leakage groups rather than individual rows. A group joins exact
duplicates, normalized near duplicates, reply/forward/thread relatives, and other answer-sharing records identified by
the frozen preparation policy. No group may cross roles. The manifest records group-policy digest, split seed, artifact
hashes, row and group counts, cross-split audit results, and explicit temporal/future, seen-identity, unseen-identity,
head/tail, and challenge cohorts where labels support them.

Bank-building and policy-tuning processes may read train and validation artifacts only. They may not read the final-test
text, labels, per-document metrics, failure examples, or a scalar derived from final-test quality. The final test is run
once for the frozen release candidate; it is never an optimization objective. Every access and its privacy-safe aggregate
outcome, including a failed or aborted run, enters an append-only public benchmark lineage. A failure may be followed by
a newly preregistered release candidate and newly sealed test, but that run must link the failed run and disclose the
changes and decisions informed by its outcome; it never replaces or hides that result. Repeatedly tuning against the same
final test or selectively surfacing only successful runs invalidates promotion.

Before access, the manifest designates exactly one prepared primary natural-content view and binds its artifact and
content policy. A promoted quality run must attest that this view contains no answer-bearing fields. The preregistered
plan freezes the deterministic 100-document, 100-distinct-group sample design and its 51,704-document frame, plus the
bank, evaluator, thresholds, performance plan, annotation/catalog/execution policies, resource ceilings, and no-tuning
rule. Outcome-dependent span, catalog, negative-document, and character denominators are bound only after independent
annotation. Evidence must preserve the exact sample membership. The combined gate and its person/contact diagnostics
cover every sampled document and the complete primary view without exclusions.

The conformance plan separately freezes content-addressed positive and negative/adversarial case artifacts, their
counts, the exhaustive synthetic label artifact, and the conformance policy hash. It requires positive support for every
active pattern. The final-test frozen target and every lineage entry bind the preregistered audit-plan hash alongside
the bank, evaluator, split, exact final-test artifact, thresholds, performance plan, source commit, and freeze time.
The final evidence separately binds both that audit plan and the complete supplied manifest. Reusing that test artifact
for another release candidate invalidates the lineage.

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

These terms are not interchangeable, and only catalog conformance directly evaluates NERB's declared-pattern contract:

- **Catalog conformance** is `correctly_detected_and_mapped_approved_cases / all_approved_positive_cases` on exhaustive
  synthetic conformance cases. Negative/adversarial cases are reported alongside it. Contract evidence requires `1.0`
  recall and zero wrong canonical mappings.
- **Catalog coverage** is `|K| / |G|`. It asks how much labeled future sensitive text was knowable from the active bank,
  independent of whether the engine found it. It evaluates bank construction, not matcher quality.
- **Natural-text cataloged exact-span recall** is `cataloged_TP / |K|`. It is a stricter occurrence diagnostic requiring
  exact span, class, and canonical identity. Its complement is the count of cataloged exact-span evaluation misses.
- **Open-world PII recall** is `TP / (TP + FN)` over all eligible independently labeled PII in scope, whether cataloged,
  matched by a generic fallback, or unknown. It evaluates a bank or discovery layer for comprehensive coverage and sits
  outside NERB's known-bank guarantee.

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

The benchmark does not assert a binomial confidence interval for quality. Its quality result is descriptive evidence for
one fixed, deterministic stratified 100-document panel selected from the 51,704-document frame. It is not an iid sample,
a corpus census, or an estimator of corpus-wide prevalence or recall. Raw support counts, stratum counts, and promotion
support floors remain visible beside every rate.

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

Bank descriptors freeze taxonomy composition as well as entity, name, alias, literal-pattern, regex-pattern, physical
artifact, canonical-serialization, native-source, and byte counts. Promotion exercises distinct 1k, 10k, 25k, and 100k
active-matcher-pattern banks. The 100k fixture has two semantic taxonomy classes backed by 318 native matcher shards
(159 per class, at most 502 patterns per shard). A non-promotable five-native-shard feasibility probe exceeded 5 GiB
and did not complete, so this cell is not evidence for a 100k small-shard topology. Active alias counts remain truthful,
and taxonomy, name/alias, and
literal/regex proportions track the evaluated bank within the contract tolerance. All four banks share one
content-addressed, versioned generator implementation and specification while allowing scale-specific seeds. These are
controlled measurements, not four unrelated cells: every scale uses the same canonical negative, medium, serial
whole-input shape; density varies on a
fixed bank, size, and synthetic generator family; size varies on a fixed bank, density, and synthetic generator family;
and serial/concurrent cells use the exact same bank, input, sample unit, and work. Unrelated real inputs cannot stand in
for controlled generated sweeps. Direct-scan inputs cover negative, sparse, normal, and dense hits; small, medium, large,
and huge documents; and both serial and machine-bounded concurrent execution.

Each lifecycle phase—source profile, source build, cold compile, helper cache miss, helper cache hit, direct bank scan,
and end to end—has an evaluated-bank decision cell. Decision-grade source-profile, source-build, and cold-compile cells
bind the exact frozen development-train artifact; performance work cannot accept the pre-split preparation source or a
sealed-test selector. Those setup cells
use 20 fresh-process samples and report median, median absolute deviation, and nearest-rank p95; p99 is unsupported and
remains null for those one-time setup phases. Their same-path stability metric is median time. Helper-cache hit/miss and
end-to-end cells use 100 samples and compare median time. All true direct whole-input and document-latency cells use
1,000 pooled samples and compare nearest-rank p99. The frozen matrix contains 19 true decision cells plus one separate
100-sample direct-cache-value comparison-support proxy. The proxy has `decision_grade: false`, compares median time, and
cannot serve as a headline, absolute gate, or break-even input. Every true direct/document block contains 100 samples;
each document block is one complete balanced pass over the exact 100-document population. Every
decision cell uses one work unit plus one positive RSS sample per timing sample with peak
RSS equal to their maximum. Fresh-process phases use zero warmups; reused-process phases use at least three. Every
decision-grade harness command must succeed, concurrency cannot exceed the recorded CPU count in any phase, and measured
peak RSS cannot exceed the recorded machine memory.

Every decision cell has same-machine stability comparisons against an exact semantic control on an identical operation
specification, source artifact, phase, bank, input, warmup policy, sample count, sample unit, work, and concurrency.
Every measured candidate/exact-twin pair is split into ten frozen paired blocks with a hash-derived, balanced
candidate-first/control-first assignment. The blocks use a balanced mix of ABBA and BAAB observation orders; the
hash-derived order is not required to alternate strictly. Reused-process paths receive fresh candidate and control worker
sessions for each block. Runner source and unit tests enforce construction order from the frozen assignment. The
verifier-observable correctness audit separately binds sample chronology, per-block PID reuse or freshness, and disjoint
candidate/control PIDs; it does not claim to observe process-creation events. Each true decision cell has exactly one
symmetric same-path metric: median for setup, helper-cache hit/miss, and end-to-end cells, and p99 for true direct
whole-input and document cells. The comparison-support proxy uses median. These exact twins measure session and order
stability, not prior-code regression.

For candidate metric `C` and control metric `B`, the frozen symmetric gap is `max(C, B) / min(C, B) - 1`, which is
equivalent to testing `abs(log(C / B))` against `log(1.05)`. A gap no greater than 5% is `within_tolerance`. A larger
gap causes all `2^10` whole-block label swaps to be enumerated with the pooled metric recomputed after every assignment.
The resulting diagnostic classifies the failed cell as `unstable` at p <= 0.05 or `inconclusive` otherwise; both are
nonpromotable. `within_tolerance` is a frozen engineering decision, not a statistical equivalence claim.

Cross-path cache-value evidence remains separate and directional. A dedicated 100-sample direct-cache-value cell joins
helper-cache hit/miss and end-to-end paths in ten four-path Williams-balanced blocks on the same evaluated bank, input,
work, and concurrency; canonical aggregate digests must prove identical mapped results first. It is a non-decision
comparison-support proxy and does not replace the 1,000-sample direct cell used for absolute p99 gates or the direct rate
used by the break-even model. Cross-path comparisons alone use directional paired-block timing-ratio MAD, and a noise
floor above the unconditional 25% ceiling is nonpromotable regardless of the directional outcome. Same-path symmetric
comparisons do not use this noise-floor policy. Comparison hashes commit comparison kind, candidate and baseline cell
IDs, metric, direction, and the applicable frozen policy, not observed values or outcomes.
Capability differences must still be stated for non-equivalent exploratory baseline measurements, which are not exact
cache-value comparisons.

Absolute results are hardware-specific. Promotion uses thresholds frozen in the public plan and same-machine repeated
stability controls and fails closed when required samples, block/session schedules, input inventories, RSS, or environment
provenance are missing. Setup cells gate median, median absolute deviation, p95, and peak RSS. Scan-bearing cells gate
median, p95, p99, and peak RSS; document cells also gate seconds per document, while whole-input cells gate
documents/second and MiB/second. Validation may tighten but cannot weaken the deliberately conservative direct-scan
policies at any required scale: document p99 at most 50 ms, whole-input median
throughput at least 100 documents/second and 1 MiB/second, p99 no slower than those same per-input throughput floors,
and peak RSS at most 8 GiB. These absolute bounds prevent a similarly slow baseline from making an impractical candidate
promotable. CI smoke timing is robustness evidence, not a substitute for the decision-grade protocol.

The value demonstration records an additive parameterized break-even model rather than inventing hosted-model prices.
Let `K` be the shared declared curation plus measured profiling and bank-build acquisition cost, `C` the measured cold
compile, `D` direct-reuse seconds per exact frozen whole-input request, and `M` exact helper-cache-miss seconds for that
same request. The two paths are `K + C + nD` and `K + nM`; because they consume the same evaluated bank, `K` is recorded
identically on both sides and cancels. Report the smallest integer `n` for which `C + nD <= nM`, where `n` is the number
of complete `whole_input_scan_requests` and the minimum is one. For the current frozen input, one request means one scan
of all 100 documents; the model never fractionalizes it into per-document costs or projects it onto an arbitrary batch.
Each path retains a `within_tolerance` same-path stability control on its decision metric, and the directional cross-path
comparison is separately identified. Generic regex, Python, external-call, or arbitrary extra-cost components cannot
satisfy the promoted model.
The value-plan hash commits the exact shared, compile, and marginal roles and sources, units, range, and declared shared
scenario, but not later measured workload values or the derived result. Promotion requires a finite supported advantage
or break-even. This model supplements privacy/quality gates; it never discounts a miss.

## Artifact Contract

The benchmark has two JSON contracts:

- `nerb.enron_manifest.v2` binds evaluator ID/digest; source ID, revision, and content hashes;
  cleaning/group/split policy hashes; the split-manifest hash; train/validation/test artifact hashes and counts; the
  primary prepared text view; bank hash; exact per-role label populations and annotation provenance; quality-denominator
  and positive/negative conformance plans; the preregistered audit-plan hash; package, native-engine, commit, and schema
  identities; exact commands; environment; and privacy-safe validation status.
- `nerb.enron_evidence.v2` cross-binds the manifest and preregistered audit-plan hashes to evaluation status, aggregate
  quality slices, catalog-conformance results, the final-test frozen target and lineage, performance banks and inputs,
  raw timing samples or references plus raw RSS samples, frozen command/spec/source-bound performance harnesses, exact
  baseline comparisons and additive value models, configured thresholds, promotion-gate results, verifier status, and
  supportable claims.

Bank provenance separately records the byte count of the physical content-addressed bank artifact and the byte count of
its canonical serialization. The performance-bank artifact reference binds the physical file hash and size; it must not
substitute the canonical serialization size when the stored JSON uses different whitespace or formatting.

Paths and commands are sanitized but remain exact enough to reproduce in an authorized environment. Private artifact
references use stable logical IDs and hashes, not workstation paths. Hash algorithms and canonicalization rules are part
of the schema contract. Missing evaluator, source, split, bank, package/engine/commit, command, or environment provenance
is an error.

Quality is explicitly `evaluated` or `not_evaluated`. Missing slices, zero eligible gold, absent independent labels, and
empty conformance cases cannot silently become zero-filled success. Non-finite numbers are invalid. A verifier recomputes
all possible rates from integer counts, checks totals and slice identities, checks manifest/evidence hashes and version
freshness, evaluates gates from recomputed source values rather than declared derived scalars, and rejects any claim
whose scope or label strength exceeds its evidence. Count-derived quality gates use exact rational comparisons against
their frozen decimal thresholds; performance gates, comparisons, value-model inputs, and claims reuse statistics
recomputed from the verified raw timing samples. Gate actuals must exactly copy their public targets, and tolerated
numeric serialization drift can never round a structured claim in the favorable direction. Performance gates may
target only those recomputed workload statistics or raw peak RSS, not downstream display fields. This
lets a clean clone verify arithmetic and claim consistency without access to private email text.

The schema and synthetic fixtures are part of the contract, but a schema-valid fixture is not real-corpus evidence.
Preparation and immutable split commands now implement the private data stages; the evaluator and verified real-corpus
evidence remain staged. Neither a prepared corpus nor a split manifest is a quality, performance, or promotion result.

## Standalone Privacy-Redaction Application Gates

The frozen benchmark asked whether the evaluated bank could be promoted as a comprehensive standalone privacy redactor.
That application-specific decision requires all applicable checks to pass:

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

The single combined person-contact application slice must contain exactly the 100 sampled documents, at least 100 total
gold spans, at least 20 documents negative across both active classes, and at least 500 union sensitive-gold characters.
Both person and contact must have nonzero gold support. These floors are applied once to the combined panel, never once
per class and never by summing document counts. Validation may tighten, but cannot weaken, the policy floors:
open-world recall at least 0.95, catalog coverage at least 0.80, cataloged recall exactly 1.0, and sensitive-character
recall at least 0.98. The corresponding ceilings are document leak rate 0.05, sensitive-character leak rate 0.02,
negative-document false-alarm rate 0.50, and over-redaction rate 0.05. Zero cataloged misses, wrong canonical mappings,
and catalog-miss documents are separate exact gates.

Structured public claims are not selected from convenient diagnostics. Standalone-redaction promotion requires the full
quality metric set
for every gate-designated slice, a passing catalog-conformance claim, and performance claims tied to the exact promoted
document-latency and whole-input-throughput workloads. Each claim repeats its exact slice or workload, scope, label
strength/completeness, bank, evaluator, source revision, benchmark identity, and environment provenance.

A failed application gate is evidence, not permission to tune on the test. Claims must name the corpus revision, benchmark
identity, bank and evaluator hashes, label strength, class/cohort scope, and machine context for performance. “No known
cataloged miss in this frozen evaluation” is supportable when true; “NERB catches all PII” is not.

Failed or aborted aggregate outcomes remain publishable in the append-only lineage. Recording a failure is mandatory
evidence; it is never itself a passing claim. These gates govern the evaluated bank's standalone-redaction claim, not
publication of the NERB package for its known-bank use case.

## Artifact Retention And Ethics

The pinned Enron dataset is already public and authorized for this benchmark. That permits agent inspection of sampled
messages; it does not create a product need to republish message text, identifiers, ranks, or per-document failure
material. Those details remain outside public benchmark evidence to preserve the blinded protocol and minimize needless
redistribution. Known annotation gaps, historical-domain bias, source integrity limitations, access terms, and intended
use must be recorded with every manifest.

Raw downloads, cleaned text, annotations, split files, real banks, aliases, match records, failure examples, and
optimization logs stay under ignored `.nerb/` paths or an equivalently access-controlled store. Encrypt them at rest
where practical, grant least-privilege access, and record an owner, purpose, creation time, retention deadline, and
deletion outcome. A production user's operational bank may have its own approved lifecycle; benchmark copies do not
inherit indefinite retention.

Git may contain only schemas, synthetic fixtures, source/policy hashes, aggregate evidence, and sanitized examples that
pass automated privacy checks. Public evidence must omit raw strings, context snippets, addresses, names, local paths,
and small slices that enable reconstruction. The public-contract scan deliberately rejects any at-sign, common SSN or
phone shape, and punctuation-wrapped local path; diagnostics are deterministic and bounded without echoing rejected
values. This includes compatibility-normalized/fullwidth identifier forms, canonical E.164 numbers, common Unicode
separators and decimal digits, formatted international numbers, compatibility-normalized path punctuation, UNC shares,
and local paths attached to command options. HTTP(S) remote paths, nested remote links, and promotion-gate JSON pointers
remain permitted, but recursively partitioned and repeatedly decoded URL payloads cannot smuggle an identifier, local
path, or file URI. Percent escapes, HTML entities, compatibility forms, and zero-width separators are normalized to a
bounded fixed point; strings that exceed that normalization budget fail closed. External sample and inventory resolvers
and trusted-lineage prefixes must use bounded exact JSON-like built-in containers and scalar types. Shared referenced
performance artifacts are normalized once per content ID and share an aggregate item budget. File loaders enforce
node, collection, and depth limits before materializing JSON as well as after parsing. Charts are regenerated solely
from the verified aggregate evidence bundle.

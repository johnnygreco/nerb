# Enron Privacy Evaluation

The evaluator keeps three questions separate:

1. **Catalog coverage:** how much independently labeled sensitive text the frozen bank knew.
2. **Catalog conformance:** whether every approved active pattern is detected and mapped exactly as declared.
3. **Open-world privacy recall:** how much sensitive text is detected whether or not it was already cataloged.

This distinction is operationally important. A matcher can conform perfectly to its catalog while still missing an
unknown person. NERB therefore reports missed spans, documents with any miss, and leaked sensitive characters before
secondary summaries such as F1.

## Independent person-name source

The auxiliary person-name evaluation uses the CMU Enron Meetings tagged-text archive from the
[official dataset page](https://www.cs.cmu.edu/~einat/datasets.html), pinned at:

```text
URL: https://www.cs.cmu.edu/~einat/EnronMeetings-XML.zip
SHA-256: e7d8dbd9e066eddd6d706a041e379ca93daf9e441a73009646ead41e94a60202
```

The page describes personal-name labels embedded in text and says the archive's train/test directories preserve the
published split. The associated [2005 paper](https://aclanthology.org/H05-1056/) defines the annotation scope: include
nicknames and misspellings, but exclude names inside email addresses and person-name substrings inside larger
organization or location names. Evaluation uses exact entity boundaries.

The pinned archive is authoritative for executable ingestion. Its verified local aggregate is:

| Archive role | Documents | `<true_name>` spans |
| --- | ---: | ---: |
| train | 729 | 1,896 |
| test | 247 | 527 |
| total | 976 | 2,423 |

These archive counts do not equal Table 1's experimental train/tune/test and name totals. NERB records the discrepancy
instead of claiming the paper directly published the archive aggregate.

Despite the historical filename, the 976 members are tagged text fragments rather than well-formed XML documents.
The parser treats only exact `<true_name>` and `</true_name>` markers as labels. It preserves non-annotation angle
constructs, rejects annotation-marker lookalikes, removes the two exact marker tokens, and records the maximal
non-whitespace labeled interval as a half-open Unicode-scalar span. It never applies generic tag stripping, whitespace
normalization, or label injection to scan text.

## Private ingestion

Raw messages and labels remain private. Ingestion reads an explicit archive through a no-follow descriptor, verifies the
whole-archive hash before parsing, validates the closed ZIP inventory without extraction, and writes a new ignored
directory transactionally:

```shell
uv run nerb download-enron-annotations \
  --output-dir .nerb/sources/cmu-enron-meetings

uv run nerb prepare-enron-annotations \
  --archive .nerb/sources/cmu-enron-meetings/EnronMeetings-XML.zip \
  --output-dir .nerb/enron-annotations/cmu-meetings-v2

uv run nerb verify-enron-annotations \
  --run-dir .nerb/enron-annotations/cmu-meetings-v2
```

The downloader has no caller-supplied URL. It accepts only the pinned HTTPS source, rejects cross-origin redirects and
encoded responses, enforces the exact byte count while streaming, verifies SHA-256 before writing, and commits the ZIP
and an aggregate receipt into a new private directory.

The private run separates marker-stripped documents from span labels. The public receipt contains only versions,
aggregate counts, artifact sizes and SHA-256 commitments, parser/span-policy identities, and privacy/promotion status.
It contains no text, label surfaces, document IDs, archive member names, or private paths.

The production archive bundle is also non-promotable on its own: verified source bytes do not prove a separate
content-level annotation review or bind the auxiliary archive to the main sealed test. Fixture mode exists only for
generated test archives and is independently marked non-promotable.

## Quality execution

`nerb.enron_quality.evaluate_enron_quality` accepts closed document, gold-span, and slice-plan mappings. It compiles the
active bank once, reuses that compiled instance for every document, converts native UTF-8 byte offsets to Unicode-scalar
indices, and returns aggregate-only evidence.

Run the generic executor over explicit private JSONL artifacts with:

```shell
uv run nerb eval-enron-quality \
  --bank .nerb/banks/enron-v2.json \
  --documents .nerb/evals/documents.jsonl \
  --gold-spans .nerb/evals/gold-spans.jsonl \
  --slice-plan .nerb/evals/quality-slices.jsonl \
  --unsupported-slices .nerb/evals/unsupported-slices.jsonl
```

Catalog membership is frozen gold metadata, not an inference from NERB's predictions. Each cataloged gold occurrence
declares the active `(entity_id, name_id, pattern_id)` under which a separate review found that occurrence qualified, or
an explicit uncataloged state. The evaluator verifies that exact pattern is active. This prevents a successful scan from
retroactively changing the catalog-coverage denominator or a name-only assertion from manufacturing coverage. The CMU
labels alone do not provide these qualifications; a bank-specific, separately reviewed binding is required.

The verifier-backed CMU adapter deliberately exposes only the training role for exploratory evaluation. Its catalog
binding file is closed JSONL with exactly one row for every verified training span and no surface text:

```json
{"document_id":"opaque-id","start":0,"end":5,"catalog_identity":{"entity_id":"person","name_id":"reviewed-name-id","pattern_id":"approved-pattern-id"}}
{"document_id":"opaque-id","start":12,"end":17,"catalog_identity":null}
```

The first form records a separately adjudicated catalog identity; `null` records an explicitly adjudicated
out-of-catalog occurrence. Missing, duplicate, or extra span rows fail closed. Run it with:

```shell
uv run nerb eval-enron-cmu-train \
  --bank .nerb/banks/enron-v2.json \
  --annotation-run .nerb/enron-annotations/cmu-meetings-v2 \
  --catalog-bindings .nerb/evals/cmu-train-catalog-bindings.jsonl
```

The adapter re-verifies the private bundle and binds its source, document, label, span-policy, and catalog-adjudication
commitments into the run fingerprints. It remains auxiliary, non-promotable evidence.

### Closed quality input contracts

Every input is strict UTF-8 JSONL: one object per line, no duplicate keys, non-finite values, unknown fields, symlinks,
or unbounded lines. Documents use Unicode text but carry no labels:

```json
{"document_id":"opaque-doc","text":"Sanitized example text","text_view":"natural_body","split_role":"validation"}
```

`split_role` is `train`, `validation`, or `test`. Gold uses half-open Unicode-scalar offsets into the exact document
text. `catalog_identity` is either `null` or a separately adjudicated active pattern qualification:

```json
{"document_id":"opaque-doc","entity_class":"person","start":0,"end":9,"catalog_identity":{"entity_id":"person","name_id":"example-person","pattern_id":"full-name"}}
```

Each slice freezes one exact document population and uses this closed shape:

```json
{"id":"person_all_validation","label_artifact_id":"reviewed-person-labels","label_strength":"independent","annotation_scope":{"entity_classes":["person"],"document_regions":["natural_body"],"span_policy_sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","exclusions":[]},"annotation_completeness":"exhaustive_within_scope","entity_class":"person","cohort":"all","split_role":"validation","text_view":"natural_body","text_view_descriptor":{"id":"natural_body","artifact_sha256":"sha256:1111111111111111111111111111111111111111111111111111111111111111","content_policy_sha256":"sha256:2222222222222222222222222222222222222222222222222222222222222222","document_regions":["natural_body"],"primary_for_quality":true,"answer_bearing_fields_included":false},"promotion_gate":false,"document_ids":["opaque-doc"]}
```

`label_strength` is `independent` or `structured_weak`; `annotation_completeness` is
`exhaustive_within_scope` or `partial`. Exhaustive independent evidence must cover the complete scanned view. A
promotion-gated slice additionally requires the all-document primary test view, no exclusions or answer-bearing fields,
and exact population coverage. Unavailable requested dimensions are separate JSONL rows:

```json
{"id":"person_head_tail","dimension":"head_tail","reason_code":"identity_frequency_unavailable"}
```

Logical IDs and reason codes are bounded privacy-safe identifiers. The public result contains aggregates plus evaluator,
policy, protocol, catalog-binding, bank, execution-adapter, contract-validator, and run fingerprints—never document IDs,
text, surfaces, or per-span outcomes. `eval-enron-quality` and `eval-enron-cmu-train` exit nonzero for an invalid bank,
unevaluated evidence, unsafe input, or failed standalone contract validation. Native collection stops at 100,000
predictions per document, and the executor rejects more than 500,000 predictions across one quality run.

The executor computes deterministic one-to-one exact-span/class counts and contract-compatible metrics:

| Privacy or utility signal | Meaning |
| --- | --- |
| `open_world_recall` | Exact-span/class recall over every eligible independently labeled occurrence. |
| `documents_with_any_miss` / `document_leak_rate` | Sensitive-positive documents containing at least one miss. |
| `sensitive_character_leak_rate` | Gold-sensitive scalar positions left uncovered by the redaction spans. |
| `catalog_coverage` | Gold occurrences independently classified as known to the active catalog. |
| `cataloged_recall` | Correctly detected and canonically mapped cataloged occurrences. |
| `cataloged_wrong_canonical` | Correct span/class detections assigned to the wrong catalog identity. |
| `precision` and `f1` | Secondary exact-span utility summaries. |
| `negative_document_false_alarm_rate` | Exhaustively negative documents with at least one in-scope prediction. |
| `over_redaction_rate` | Predicted scalar positions outside gold divided by all evaluated scalar positions. |

The committed sanitized tests intentionally produce different catalog and open-world outcomes:

| Sanitized fixture signal | Count | Rate |
| --- | ---: | ---: |
| Approved synthetic catalog cases correctly mapped | 9 / 9 | 1.0 conformance recall |
| Independently labeled occurrences cataloged before scanning | 2 / 3 | 0.667 catalog coverage |
| Cataloged occurrences correctly mapped | 1 / 2 | 0.5 cataloged recall |
| All independently labeled occurrences exactly detected | 2 / 3 | 0.667 open-world recall |
| Sensitive-positive documents with a miss | 1 / 3 | 0.333 document leak rate |

The conformance and natural-text rows come from separate purpose-built fixtures, so this is an arithmetic demonstration,
not a benchmark claim. It shows why perfect catalog conformance cannot substitute for open-world privacy recall.

Only `independent + exhaustive_within_scope` evidence whose annotation regions cover the complete scanned text view can
support false positives, open-world recall, negative-document alarms, or character-level utility. Partial-region,
partial independent, and structured-weak labels retain labeled-span and catalog diagnostics, while unsupported metrics
are `null`. Empty populations and zero-label partial/weak slices are explicit unsupported results, not zero-filled
passing evidence.

Slice plans are frozen before execution and bind exact document populations. Supported dimensions include class,
split role, text view, exhaustively negative documents, and any train-derived known/novel or head/tail membership supplied
by the immutable split artifacts. CMU surface recurrence is not person-identity recurrence and must be labeled as a
diagnostic if used. Missing identity or frequency linkage is reported as unsupported.

The fixed benchmark is a finite population; it makes no independent-and-identically-distributed sampling claim and does
not publish a binomial confidence interval. Raw support counts and promotion floors stay beside every rate.

## Catalog conformance

Conformance uses separately approved synthetic positive and negative JSONL artifacts. Every active pattern needs at
least one exact positive witness. The full active bank is compiled once and scanned as a whole so real priority,
leftmost, boundary, and overlap shadowing remains visible.

```shell
uv run nerb eval-enron-conformance \
  --bank .nerb/banks/enron-v2.json \
  --positive-cases .nerb/evals/conformance-positive.jsonl \
  --negative-cases .nerb/evals/conformance-negative.jsonl \
  --output-dir .nerb/evals/conformance-run
```

Positive cases bind the expected entity, canonical name, pattern, kind, string, and exact UTF-8 byte span. A same-span
prediction under another canonical identity is a wrong mapping; detection by another pattern does not prove the target
pattern. Any prediction in a negative case fails that case. The frozen adversarial suite covers casing, punctuation,
whitespace, Unicode, substring boundaries, overlaps, HTML residue, signatures, malformed mail, and clean negatives.

The gate is intentionally strict: every active pattern must have support, recall must be exactly `1.0`, wrong canonical
mappings must be zero, and unexpected negative matches must be zero. Zero active patterns or empty positive/negative
artifacts produce `evaluated=false`, `recall=null`, and `passed=false`. An otherwise evaluated plan with incomplete
active-pattern support remains evaluated and fails the gate.

### Closed conformance input contracts

Positive and negative inputs are separate strict JSONL artifacts. A sanitized positive row is:

```json
{"schema_version":"nerb.enron_conformance_positive_case.v2","case_id":"case_full_name","text":"Example Person","tags":["casing"],"expected":[{"entity_id":"person","name_id":"example-person","pattern_id":"full-name","pattern_kind":"literal","canonical_name":"Example Person","string":"Example Person","start":0,"end":14}]}
```

`start` and `end` are half-open UTF-8 byte offsets, unlike quality gold's scalar offsets. Every expected identity must
name an active pattern and exactly agree with its canonical name, pattern kind, string, and span. A negative row is:

```json
{"schema_version":"nerb.enron_conformance_negative_case.v2","case_id":"case_boundary_negative","text":"XExample PersonY","tags":["boundary","negative"],"reason_code":"substring_boundary"}
```

Case IDs and reason codes are opaque bounded identifiers, text must be non-empty, and tags come from `boundary`,
`casing`, `html`, `malformed`, `negative`, `overlap`, `punctuation`, `signature`, `unicode`, and `whitespace`. The frozen
suite must cover every tag and include a boundary-negative case. The CLI commits raw cases and per-case outcomes only to
the requested private audit directory; stdout remains aggregate-only. It exits nonzero for invalid/unevaluated inputs or
any failed conformance gate. The configured per-case match limit is enforced while the native engine is collecting
matches, before Python enrichment or sorting.

## Fingerprints and guarantee boundary

Quality protocol fingerprints bind evaluator and contract source, the shared Python/native execution adapter, label
schema, metric policies, exact document/text commitments, gold spans, split roles, text views, and slice membership.
Run fingerprints additionally bind the exact bank, catalog qualifications, contract validation, and result. Conformance
fingerprints bind evaluator/contract source, the shared execution adapter and native binary, policy, bank, engine, and
positive/negative case artifacts. Changing an evaluator, engine adapter, label/split input, case artifact, or bank
therefore invalidates comparison reuse.

CMU Meetings is independent auxiliary Enron evidence, not the main corpus's sealed final test and not proof of canonical
person identity. The archive does not provide labels for the full NERB taxonomy, and its public materials do not document
a content-level adjudication protocol or redistribution license. Keep it research/aggregate-only, keep its test role
frozen from tuning, and never use it to claim guaranteed detection of unknown PII.

The one deterministic guarantee remains narrower and testable: NERB must detect and correctly map every approved active
catalog pattern under its declared normalization, boundary, and overlap semantics. Open-world privacy recall measures
what lies beyond that guarantee.

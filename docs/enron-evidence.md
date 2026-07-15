# Enron Evidence and Interpretation

## Outcome

**NERB's known-bank contract evidence passed.** Across all 13,201 active patterns, the exhaustive conformance suite
detected and correctly mapped all 39,604 approved positive cases. It also produced zero wrong canonical mappings and
zero unexpected matches on 1,210 required negative and adversarial cases.

That is the guarantee NERB is designed to make: given the same validated bank, engine identity, scan options, and input
bytes, it deterministically detects qualifying occurrences under each pattern's declared normalization, boundary,
priority, and overlap semantics. NERB does not guarantee discovery of an entity that has no qualifying pattern in the
bank.

The same evidence supports a separate conclusion: **this constructed Enron bank is not eligible as a comprehensive
standalone PII redactor.** It cataloged only 146 of 1,393 independently labeled person/contact spans. That limitation
belongs to the bank-building application, not to NERB package-release eligibility.

| Question | Result | Meaning |
| --- | ---: | --- |
| Does NERB honor the supplied bank contract? | pass | 39,604/39,604 approved positives across 13,201/13,201 patterns; 1,210/1,210 required negatives clean. |
| Does a strict natural-text exact-span diagnostic agree? | 142/146 | Four catalog-qualified contact cases were not exact span/class/canonical true positives; no canonical mapping was wrong. |
| How much of the labeled population did this bank know? | 146/1,393 | The 10.48% catalog coverage is a bank-construction result, not matcher recall. |
| Can this bank stand alone as a comprehensive PII redactor? | no | Its preregistered open-world recall and leakage gates failed. |

The source dataset is public. The committed
[aggregate evidence bundle](https://github.com/johnnygreco/nerb/tree/main/evidence/enron) still excludes source text,
bank values, document IDs, span surfaces, and private paths so the publication boundary also works for sensitive
organizational corpora.

## Known-bank contract evidence

| Contract evidence | Result |
| --- | ---: |
| Active patterns with approved positive support | 13,201 / 13,201 |
| Approved positive cases detected and correctly mapped | 39,604 / 39,604 |
| Required negative/adversarial cases without an unexpected match | 1,210 / 1,210 |
| Conformance misses | 0 |
| Wrong canonical mappings | 0 |

Synthetic conformance deliberately exercises case, whitespace normalization, boundaries, regex behavior, overlap, and
canonical mapping according to each active pattern's contract. It is exhaustive over the approved generated cases; it
does not claim that the bank contains every possible person or identifier.

The independent natural-text panel asks a stricter occurrence-level question requiring exact span, class, and canonical
mapping. It found 142/146 catalog-qualified occurrences exactly:

| Natural-text catalog diagnostic | Combined | Contact | Person |
| --- | ---: | ---: | ---: |
| Cataloged gold occurrences | 146 | 126 | 20 |
| Exact true positives | 142 | 122 | 20 |
| Exact-span evaluation misses | 4 | 4 | 0 |
| Cataloged exact-span recall | 97.26% | 96.83% | 100.00% |
| Wrong canonical mappings | 0 | 0 | 0 |

All contact-sensitive characters were nevertheless covered. The four cases therefore remain important exact-record
diagnostics without implying that contact text leaked or that the 1,247 uncataloged person mentions were matcher
failures.

## Bank coverage, outside the guarantee

Catalog coverage is the fraction of independently labeled occurrences that qualified under an active bank pattern
before looking at predictions. Open-world recall uses every labeled occurrence as its denominator, including entities
absent from the bank. These metrics evaluate population coverage of a bank or a generic discovery layer; they are not
NERB's bank-relative matcher recall.

| Class | All gold spans | Cataloged | Outside bank | Catalog coverage |
| --- | ---: | ---: | ---: | ---: |
| Combined | 1,393 | 146 | 1,247 | 10.48% |
| Contact | 126 | 126 | 0 | 100.00% |
| Person | 1,267 | 20 | 1,247 | 1.58% |

The [generated coverage plot](https://github.com/johnnygreco/nerb/blob/main/evidence/enron/figures/bank-coverage.svg)
shows the full decomposition: 142 cataloged exact matches, four cataloged exact-span diagnostics, and 1,247 spans outside
the bank. The outside-bank group accounts for 99.68% of the 1,251 exact-span misses.

## Standalone privacy-redaction assessment

The preregistered privacy gate intentionally asked whether the constructed bank could redact every in-scope person and
contact occurrence, including unknown identities. This bank failed that broader application test:

| Application metric | Combined result | Frozen requirement | Decision |
| --- | ---: | ---: | --- |
| Open-world recall | 10.19% | at least 95% | fail |
| Catalog coverage | 10.48% | at least 80% | fail |
| Cataloged exact-span recall | 97.26% | 100% | fail: four exact-span diagnostics |
| Sensitive-character recall | 21.34% | at least 98% | fail |
| Document leakage | 89.86% | at most 5% | fail |
| Sensitive-character leakage | 78.66% | at most 2% | fail |
| Precision | 95.30% | diagnostic | high, but not compensating |
| Negative-document false-alarm rate | 0.00% | at most 50% | pass |
| Over-redaction | 0.04% | at most 5% | pass |

All 11,733 leaked sensitive characters and all 59 documents with a leaked sensitive character were in the person slice,
where only 20 of 1,267 gold occurrences were cataloged. This is why the correct conclusion is specific: do not use this
bank alone as a comprehensive PII redactor. It is not a reason to prevent release of NERB for known-bank matching.

## Performance and scale

The runtime architecture passed on an Apple M4 with 10 CPU cores and 16 GiB memory:

| Workload | Result |
| --- | ---: |
| Evaluated 13,201-pattern bank, 100-document direct scan | 0.699 ms median; 143,057 documents/s |
| Per-document direct scan | 9.021 µs median; 55.250 µs p95 |
| Cold compilation | 7.792 s median |
| Full train-source bank build | 334.988 s median |
| 100,000-pattern controlled scale cell | 6,811 documents/s |

The full-source capacity run also passed its runtime, memory, disk, progress, observation-cadence, source-conservation,
and sealed-state gates. These results establish that compile-once/scan-many is fast enough for the measured workloads;
they neither create missing bank entries nor weaken the standalone-redaction assessment.

## Why this evidence is decision-grade

Decision-grade means the evidence is strong enough to answer its stated question. The bank, inputs, thresholds, sample,
and workloads were frozen first; the sealed test was accessed once; gold labels were independently produced and
reviewed; every prediction case was audited; and the aggregate result is tamper-evident and reproducible without private
working artifacts.

Different evidence answers different decisions. Exhaustive conformance supports NERB's known-bank contract. The natural
panel exposes exact-record diagnostics. The open-world panel rejects this bank for comprehensive standalone redaction.
The performance run supports the compile-once/scan-many architecture. None substitutes for another.

The 100-document panel intentionally over-samples supported strata and is not iid. Its quality measurements describe
that frozen panel; they are not a corpus-wide prevalence estimate, census, or rare-class estimate.

## Verify and regenerate

From a clean checkout:

```shell
uv run nerb verify-enron-evidence --bundle evidence/enron
uv run nerb render-enron-evidence \
  --bundle evidence/enron \
  --output-dir /tmp/nerb-enron-render
```

The normal verifier authenticates the bundle, recomputes arithmetic, validates its closed artifact inventory, and checks
that the Markdown and SVGs are generated from the committed aggregates. A workflow specifically requiring a
comprehensive standalone redaction bank should add:

```shell
uv run nerb verify-enron-evidence \
  --bundle evidence/enron \
  --require-standalone-redaction-eligible
```

That application-specific check fails for this bank by design. It is not a NERB package-release check.

## Intelligence-cache value

The product workflow remains source → reviewed candidates → curated bank → compile once → scan many. Approved aliases
map text to canonical identity metadata so later messages can be routed, redacted, joined to application records, or
audited deterministically. The
[fictitious executable example](https://github.com/johnnygreco/nerb/tree/main/examples/intelligence_cache) shows the
contract end to end: qualifying known identities are mapped; an identity absent from the bank is outside the guarantee.

Use the [benchmark charter](enron-benchmark.md) for the exact guarantee and application gate, the
[bank-construction guide](enron-bank-building.md) for candidate provenance, and the
[performance guide](performance.md) for workload semantics.

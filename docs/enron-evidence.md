# Enron Evidence and Decision

## Outcome

**Do not ship the evaluated bank for privacy redaction.** The evidence is valid and decision-grade, but the bank failed
the preregistered quality gates. In the independently annotated 100-document panel it missed 1,251 of 1,393 sensitive
spans, leaving at least one miss in 62 of 69 documents that contained sensitive gold text.

Decision-grade does not mean “passed.” It means the evidence is strong enough to support the actual ship/no-ship
decision: the sample and thresholds were frozen first, the sealed test was accessed once, the gold was independently
annotated and reviewed, the score was computed once, every error case was audited, and the aggregate result is
tamper-evident and reproducible without the private working artifacts. Here, that process supports a confident no-ship
decision.

The source dataset is public. The committed [aggregate evidence bundle](https://github.com/johnnygreco/nerb/tree/main/evidence/enron)
still excludes source text, bank values, document IDs, span surfaces, and private paths so the same publication boundary
works for sensitive organizational corpora.

## Metrics users care about

For a privacy-redaction workflow, recall and leakage are primary. Precision and over-redaction matter, but high precision
cannot compensate for leaving sensitive text behind.

| Metric | Combined result | Required | Decision |
| --- | ---: | ---: | --- |
| Open-world recall | 10.19% | at least 95% | fail |
| Catalog coverage | 10.48% | at least 80% | fail |
| Cataloged recall | 97.26% | 100% | fail: 4 cataloged misses |
| Sensitive-character recall | 21.34% | at least 98% | fail |
| Document leakage | 89.86% | at most 5% | fail |
| Sensitive-character leakage | 78.66% | at most 2% | fail |
| Precision | 95.30% | diagnostic | high, but not compensating |
| Negative-document false-alarm rate | 0.00% | at most 50% | pass |
| Over-redaction | 0.04% | at most 5% | pass |

Contact detection was much stronger than person-name detection: contact open-world recall was 96.83%, while person recall
was 1.58%. This is why a combined score alone is insufficient. The bank's 100% synthetic catalog-conformance result
proves that all 13,201 approved patterns behave as declared; it does not prove that the catalog covers unknown people or
that every cataloged occurrence matches in natural text.

## Sample and audit scope

- Source: 517,401 public input rows, with 517,179 prepared records after 222 verified MIME-structure rejections.
- Immutable split: 413,752 train, 51,723 validation, and 51,704 sealed-test documents; no leakage group crosses roles.
- Gold panel: 100 documents selected from 11,625 test groups by the frozen deterministic stratified design.
- Gold support: 1,393 spans, 14,916 sensitive characters, 69 positive documents, and 31 exhaustive negatives.
- Review: two blind full-document passes, blind adjudication, independent disagreement/agreement review, prediction-blind
  catalog qualification, one scoring run, and audit of all 1,298 committed prediction cases.
- Terminal audit: zero unresolved cases and zero credible gold defects.

The panel intentionally over-samples supported strata and is not iid. Reported quality is scoped to this frozen panel; it
is not a census, corpus-wide prevalence estimate, or rare-class estimate.

## Performance and scale

The performance decision passed on an Apple M4 with 10 CPU cores and 16 GiB memory:

| Workload | Result |
| --- | ---: |
| Evaluated 13,201-pattern bank, 100-document direct scan | 0.699 ms median; 143,057 documents/s |
| Per-document direct scan | 9.021 µs median; 55.250 µs p95 |
| Cold compilation | 7.792 s median |
| Full train-source bank build | 334.988 s median |
| 100,000-pattern controlled scale cell | 6,811 documents/s |

The full-source capacity run also passed its runtime, memory, disk, progress, observation-cadence, source-conservation,
and sealed-state gates. These results show that compile-once/scan-many is technically fast enough. They do not rescue the
failed recall and leakage result.

## Verify and regenerate

From a clean checkout:

```shell
uv run nerb verify-enron-evidence --bundle evidence/enron
uv run nerb render-enron-evidence \
  --bundle evidence/enron \
  --output-dir /tmp/nerb-enron-render
```

The normal verifier succeeds because the terminal no-ship evidence is internally valid. Release automation should use:

```shell
uv run nerb verify-enron-evidence \
  --bundle evidence/enron \
  --require-quality-eligible
```

That command fails for this bundle by design. Verification covers the benchmark manifest and evidence contracts,
metric arithmetic, thresholds, audit-stage commitments, performance inventories and raw aggregate samples, capacity
receipt chain, artifact hashes, generated Markdown/SVGs, closed file inventory, and aggregate privacy scan.

## Intelligence-cache value

The useful product workflow remains source → reviewed candidates → curated bank → compile once → scan many. Approved
aliases map text to canonical identity metadata, so later messages can be routed, redacted, or joined to application
records deterministically. The [fictitious executable example](https://github.com/johnnygreco/nerb/tree/main/examples/intelligence_cache)
shows this end to end, including the critical limitation: an unknown identity remains undetected when it is absent from
the reviewed bank.

Use the [benchmark charter](enron-benchmark.md) for the threat model and gates, the
[bank-construction guide](enron-bank-building.md) for candidate provenance, and the
[performance guide](performance.md) for workload semantics.

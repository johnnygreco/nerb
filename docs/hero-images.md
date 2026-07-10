# Benchmark Figure Evidence Policy

> **Enron/autoresearch figures were historical v1 artifacts.** The unmarked
> `enron-quality-performance.png` and `autoresearch-objective.png` files have been removed. Their retained aggregate
> measurements do not satisfy the [Enron v2 charter](enron-benchmark.md) and are explicitly marked historical. Do not
> use them as evidence for a current quality, privacy, speed, or product claim.

Benchmark figures should make verified measurements easier to understand. They are not evidence by themselves: every
public number must trace to a versioned, privacy-safe aggregate bundle whose provenance, arithmetic, evaluator identity,
and claim scope can be verified from a clean clone.

## Current Asset Status

Committed maintainer-facing assets live under `examples/artifacts/hero-images/`:

| Asset | Status | Permitted use |
| --- | --- | --- |
| `enron-quality-performance.png` | Removed; historical v1, unsupported for current claims | Repository history and migration review only |
| `autoresearch-objective.png` | Removed; historical v1 F1 objective, incompatible with v2 policy | Repository history and migration review only |
| Enron/autoresearch sections of `hero_measurements.json` | Historical v1 inputs | Reproducing or auditing the historical image only; not v2 evidence |
| `scale-100k-entities.png` and its synthetic measurements | Synthetic engine illustration, not Enron v2 evidence | Clearly labeled synthetic scale discussion with workload and machine caveats |

The unmarked historical Enron/autoresearch PNGs are no longer committed. Retained aggregate JSON carries an explicit
historical claim status. The old `examples/generate_benchmark_hero_images.py` Enron/autoresearch workflow consumes v1
benchmark artifacts, has no v2 mode, requires explicit historical opt-in, and watermarks regenerated plots; rerunning it
does not upgrade the output.

## V2 Figure Requirements

Later Enron v2 figures must consume only a verified `nerb.enron_evidence.v2` aggregate bundle bound to a validated
`nerb.enron_manifest.v2`. The figure source must:

- reject evidence whose promotion, arithmetic, provenance, privacy scan, or claim-consistency verification failed;
- label independent, structured-weak, synthetic-conformance, and unlabeled slices distinctly;
- show missed sensitive spans, leaked sensitive characters, and documents with any miss before precision/F1;
- distinguish catalog coverage, catalog conformance, natural cataloged recall, and open-world privacy recall;
- show raw numerators/denominators or make them available in the adjacent verified bundle;
- separate one-time build/compile costs from direct compile-once/scan-many latency and throughput;
- include bank/workload hashes and enough machine/runtime identity to scope performance; and
- avoid raw text, aliases, names, addresses, per-document failures, private paths, or small reconstructable cohorts.

No chart may imply that catalog conformance guarantees detection of uncataloged PII. No quality chart may combine label
strengths into an unlabeled aggregate. No performance chart may compare mismatched bank, corpus, workload, evaluator, or
environment fingerprints without an explicit non-comparability warning.

## Synthetic Scale Figure

The current synthetic scale asset uses deterministic compact JSON banks with one active fixed-width, word-bounded
literal pattern per entity and a capped generated scan document. It can illustrate compile, cache, and source-size shape
across its labeled bank sizes. It does not establish Enron quality, realistic PII coverage, portable latency, or a
production service-level objective. Keep its synthetic-workload and same-machine comparison caveats adjacent whenever it
is used.

## Refresh And Promotion

There is intentionally no v2 Enron figure-generation command yet. Later implementation must add the verified aggregate
evidence and regeneration path together. A refresh is promotable only when:

1. the aggregate input and every rendered number pass the v2 verifier;
2. the generator reads no private source or per-document artifact;
3. titles, axes, legends, alt text, captions, and adjacent prose name the same scope and label strength;
4. the evidence bundle, generator change, and rendered assets land in one reviewed change; and
5. stale v1 figures and prose are removed or remain unmistakably quarantined.

Do not crop away axes, units, cohort/label-strength markers, or provenance notes. A visually cleaner but less qualified
figure is not an acceptable benchmark claim.

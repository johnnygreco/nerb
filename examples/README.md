# NERB Agent Showcase

These examples show NERB in its current shape: a Rust-backed regex NER engine for agents that maintain local
intelligence caches, cite byte offsets, and promote detector-bank changes through validation and numerical checks.

Run from the repository root:

```shell
uv run --with matplotlib==3.10.9 python examples/generate_showcase.py --output-dir /tmp/nerb-showcase
uv run nerb validate-bank --bank examples/banks/security_ops.json
uv run nerb validate-bank --bank examples/banks/revenue_ops.json
uv run nerb validate-bank --bank examples/banks/compliance_ops.json
uv run nerb extract-file --bank examples/banks/security_ops.json --file examples/documents/security_ops.txt
uv run nerb extract-report --bank examples/banks/revenue_ops.json --file examples/documents/revenue_ops.txt
uv run nerb benchmark-bank --bank examples/banks/compliance_ops.json --benchmark-iterations 3
```

The showcase generator writes to a scratch directory so it does not dirty the checkout with local timing and PNG
differences. To refresh the committed artifacts, run the same command with `--output-dir examples/artifacts`.

`generate_showcase.py` writes machine-readable outputs and matplotlib figures:

- `extractions/*.json`: raw extraction responses with deterministic byte offsets.
- `reports/*.json`: report responses with explanations, context, summaries, and metadata.
- `benchmarks/*.json`: local timing snapshots for each domain bank.
- `scale/scale_measurements.json`: generated 1k, 4k, and 10k-pattern scale measurements.
- `figures/ner_detection_*.png`: detection images built from actual NERB records.
- `figures/scale_*.png`: the main speed-at-scale numerical demonstration.
- `figures/benchmark_*.png`: small domain-bank timing figures.

The banks are intentionally small but domain-specific:

- `security_ops.json`: incident tickets, CVEs, cloud services, severities, and runbooks.
- `revenue_ops.json`: accounts, products, commercial artifacts, regions, and account health.
- `compliance_ops.json`: audit frameworks, controls, evidence artifacts, systems, and data boundaries.

Additional committed assets under `artifacts/hero-images/` need careful interpretation. The unmarked Enron quality and
held-out-F1 autoresearch PNGs were removed; retained corresponding measurements are explicitly marked historical v1.
They do not satisfy the privacy-first Enron v2 contract and must not support current public claims. The existing
benchmark-hero generator is v1-only, requires explicit historical opt-in, and watermarks those panels; rerunning it does
not produce v2 evidence. See the [figure evidence policy](../docs/hero-images.md) and [Enron v2
charter](../docs/enron-benchmark.md).

The scale figures are generated from deterministic synthetic JSON banks rather than committed large fixtures. They show
how compile time, warm extraction, and process-local bank caching behave on a mostly-literal synthetic workload as an
agent cache grows from 1,000 to 100,000 active patterns. The hero scale scan uses a capped generated target document, so
the numbers are local illustrative measurements for comparing runs on the same machine rather than portable package-wide
performance claims or Enron v2 evidence.

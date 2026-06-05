# NERB Agent Showcase

These examples show NERB in its current shape: a Rust-backed regex NER engine for agents that maintain local
intelligence caches, cite byte offsets, and promote detector-bank changes through validation and numerical checks.

Run from the repository root:

```shell
uv run --with matplotlib python examples/generate_showcase.py
uv run nerb validate-bank --bank examples/banks/security_ops.json
uv run nerb validate-bank --bank examples/banks/revenue_ops.json
uv run nerb validate-bank --bank examples/banks/compliance_ops.json
uv run nerb extract-file --bank examples/banks/security_ops.json --file examples/documents/security_ops.txt
uv run nerb extract-report --bank examples/banks/revenue_ops.json --file examples/documents/revenue_ops.txt
uv run nerb benchmark-bank --bank examples/banks/compliance_ops.json --benchmark-iterations 3
```

`generate_showcase.py` writes machine-readable outputs and matplotlib figures under `examples/artifacts/`:

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

The scale figures are generated from deterministic synthetic JSON banks rather than committed large fixtures. They show
how warm extraction and process-local bank caching behave as an agent cache grows from 1,000 to 10,000 active patterns
and from 50 KB to 300 KB of scanned text. The numbers are local illustrative measurements, so use them to compare runs
on the same machine rather than as portable package-wide performance claims.

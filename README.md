# Named Entity Regex Builder (NERB)

[![CI](https://github.com/johnnygreco/nerb/actions/workflows/tests.yml/badge.svg)](https://github.com/johnnygreco/nerb/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/johnnygreco/nerb/blob/main/LICENSE)

NERB is a Python package, CLI, and MCP server for validated named-entity regex banks. It lets you define curated entity
names and aliases, validate them before use, scan text locally with a Rust-backed engine, and return deterministic
JSON records for agents, services, and CI gates.

Use NERB when you need:

- local, explainable extraction for known entities such as companies, people, products, codes, accounts, or domains;
- stable byte-offset records that agents can cite, patch, diff, evaluate, and promote;
- one shared extraction surface across Python code, shell commands, and MCP clients;
- Rust-backed matching performance without moving authoring, validation, and workflow control out of Python.

## Installation

```shell
pip install --upgrade nerb
nerb --help
```

NERB requires Python 3.10 or newer. Published releases include the Rust extension in CPython 3.10 through 3.14 wheels
for Linux x86_64 (`manylinux_2_28`), macOS universal2 (x86_64 and arm64), and Windows x86_64. Source installs and other
platform builds require a Rust toolchain with `cargo` available on `PATH`.

From a source checkout:

```shell
git clone https://github.com/johnnygreco/nerb.git
cd nerb
make sync
uv run nerb --help
```

## Quickstart

JSON banks are the main format for agent and service workflows. A bank stores entity types, canonical names, literal or
regex patterns, statuses, metadata, and optional eval references in one validated JSON object. See
[`docs/schemas.md`](docs/schemas.md) for the complete bank schema, extraction record contracts, eval JSONL format, and a
copyable minimal `company.json`.

Validate and extract:

```shell
nerb validate-bank --bank company.json
nerb extract-text --bank company.json --text "Send this to Acme Corp today."
nerb extract-file --bank company.json --file email.txt
nerb extract-report --bank company.json --file email.txt
```

Extraction responses are JSON. Records include canonical names, matched strings, byte offsets, JSON-bank IDs, pattern
kind, and the current captures object.

Agent repair and promotion commands use the same JSON-compatible response style:

```shell
nerb apply-patches --bank company.json --patch patches.json
nerb diff-banks old-company.json new-company.json
nerb eval-bank --bank company.json
nerb benchmark-bank --bank company.json
nerb regress-bank --old-bank old-company.json --new-bank new-company.json
```

`apply-patches` accepts RFC 6902 JSON Patch operations, validates the patched candidate, and returns diagnostics with
the candidate response. `regress-bank` combines diff, eval, and benchmark checks so a bank update can be promoted by a
machine-readable gate.

## Python API

Use JSON-bank helpers for agent, service, and test integrations:

```python
from nerb import extract_text, load_bank, validate_bank

bank = load_bank("company.json")

validation = validate_bank(bank)
result = extract_text(bank, "Send this to Acme Corp today.")

print(validation["valid"])
print(result["records"])
```

For direct source-bank scanning, use the Rust-backed `Bank` API:

```python
from nerb import Bank

bank = Bank.from_source_bytes(b'{"ARTIST":{"Rush":"Rush"}}', format_hint="json")
records = bank.scan_text("Rush played in Toronto.")
```

`Bank.scan_text` returns records with `entity`, `canonical_name`, `surface_name`, `string`, `start`, `end`, and
`offset_unit`. Byte offsets are the default record contract across the CLI, Python helpers, and MCP tools.

Other public helpers include `apply_bank_patches`, `bank_stats`, `benchmark_bank`, `canonicalize_bank`, `diff_banks`,
`eval_bank`, `extract_batch`, `extract_file`, `extract_report`, `explain_match`, `hash_bank`, `regress_bank`, and
`validate_bank_schema`.

## MCP Server

NERB ships a local stdio MCP server for agents that should validate, patch, diff, scan, report, evaluate, benchmark, or
regress banks without reimplementing file handling or serialization.

```shell
nerb-mcp --version
```

Minimal installed-package client config:

```json
{
  "mcpServers": {
    "nerb": {
      "command": "nerb-mcp"
    }
  }
}
```

From a source checkout, point the client at the repo:

```json
{
  "mcpServers": {
    "nerb": {
      "command": "uv",
      "args": ["run", "nerb-mcp"],
      "cwd": "/path/to/nerb"
    }
  }
}
```

The MCP tools mirror the Python and CLI surfaces: JSON-bank validation, patching, diffing, extraction, reporting, eval,
benchmarking, regression, stats, and match explanation. Config-backed extraction tools are also available for YAML
detector configs.

## YAML Detector Configs

YAML detector configs are a compact authoring format for simple regex extraction:

```yaml
ARTIST:
  Pink Floyd: 'Pink\sFloyd'
  The Who: '[Tt]he\sWho'

GENRE:
  _flags: IGNORECASE
  Rock: '(?:progressive\s)?rock'
```

Common commands:

```shell
nerb init --config detectors.yaml
nerb add ARTIST "Pink Floyd" 'Pink\sFloyd' --config detectors.yaml
nerb validate --config detectors.yaml
nerb doctor --config detectors.yaml --format json
nerb extract ARTIST document.txt --config detectors.yaml --format json
nerb extract --all --text "Pink Floyd played progressive rock." \
  --detector 'ARTIST:Pink Floyd=Pink\sFloyd' \
  --detector 'GENRE:Rock=rock' \
  --format json
```

Config path resolution is explicit `--config`, then `NERB_CONFIG_PATH`, then the platform user config path. YAML
extraction uses the same Rust-backed `Bank` scanner and byte-offset record contract.

## Performance

NERB uses Python as the authoring and control plane, and Rust as the matching data plane. Literal and regex patterns are
canonicalized into Rust detector metadata, scanned natively, then projected into stable JSON records. Compiled banks are
cached in process by canonical bank hash, engine version, compile options, and platform dimensions.

The final Rust engine gate covers conformance, dense memory, mode strategy, wheel smoke tests, and a representative
synthetic medium bank with 1,000 entities. See [`docs/performance.md`](docs/performance.md) and
[`docs/rust-engine-gates.md`](docs/rust-engine-gates.md) for reproducible benchmark and release-gate evidence.

## Development

```shell
make sync
make check
make build
```

`make check` runs Ruff linting and formatting checks, `mypy src/nerb`, `ty check`, and pytest. `make build` builds and
validates the source distribution plus the local platform wheel with `twine check --strict`.

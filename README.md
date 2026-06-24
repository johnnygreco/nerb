# Named Entity Regex Builder (NERB)

[![CI](https://github.com/johnnygreco/nerb/actions/workflows/tests.yml/badge.svg)](https://github.com/johnnygreco/nerb/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/johnnygreco/nerb/blob/main/LICENSE)

NERB is a Python package, CLI, and MCP server for validated named-entity regex banks. It lets you define curated entity
names and aliases, validate them before use, scan text locally with a Rust-backed engine, and return deterministic
JSON records for agents, services, and CI gates.

The full documentation site is published at <https://johnnygreco.dev/nerb/>. It includes the quickstart, workflow
guides, schema reference, interface guide, anonymization notes, and performance evidence.

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
[`docs/quickstart.md`](docs/quickstart.md) for a copyable minimal `company.json`, and [`docs/schemas.md`](docs/schemas.md)
for the complete bank schema, extraction record contracts, and eval JSONL format.

After saving the minimal `company.json` from the quickstart, validate and extract:

```shell
nerb validate-bank --bank company.json
nerb extract-text \
  --bank company.json \
  --text "Send this to Acme Corp today."
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
nerb regress-bank \
  --old-bank old-company.json \
  --new-bank new-company.json
```

`apply-patches` accepts RFC 6902 JSON Patch operations, validates the patched candidate, and returns diagnostics with
the candidate response. `regress-bank` combines diff, eval, and benchmark checks so a bank update can be promoted by a
machine-readable gate.

## Anonymization And De-Anonymization

NERB can replace extracted entities with stable redaction tokens or pseudonyms. Reversible workflows use an explicit
local replacement database; that database is sensitive when it stores originals.

Reversible redaction with a JSON bank:

```shell
nerb replacement-db init --db replacements.json --reversible
nerb anonymize-text --bank people.json --db replacements.json \
  --text "John Smith joined." --mode redact --save-db
nerb deanonymize-text --db replacements.json --text "[PERSON_0001] joined."
```

Config-backed anonymization uses the Rust-resolved YAML detector records. Because YAML configs do not have JSON-bank
`name_id` values, initialize or configure the replacement DB with `canonical` or `surface` assignment scope:

```shell
nerb replacement-db init --db config-replacements.json --reversible --assignment-scope canonical
nerb anonymize-config-text --config detectors.yaml --db config-replacements.json \
  --text "Miles Davis met M. Davis." --mode redact --save-db
```

Pseudonyms require a replacement set and are not restored by default:

```shell
nerb replacement-db init --db pseudonym-replacements.json --reversible
nerb replacement-db add-set --db pseudonym-replacements.json --set person_names \
  --candidate "Mikey Law" --candidate "Nina Vale"
nerb replacement-db set-entity --db pseudonym-replacements.json --entity person \
  --mode pseudonym --set person_names --store-originals
nerb anonymize-text --bank people.json --db pseudonym-replacements.json \
  --text "John Smith joined." --mode pseudonym --save-db
nerb deanonymize-text --db pseudonym-replacements.json --text "Mikey Law joined." --restore-pseudonyms
```

Default CLI response metadata omits originals, replacement values, raw assignment keys, fingerprints, bank hashes, and
replacement DB hashes. The transformed `text` still contains replacement values by design. Python and MCP anonymization
response metadata include replacement values because they are already present in the transformed text, but still omit
originals, raw keys, fingerprints, and hashes by default. Use `--include-originals` or
`--include-sensitive-metadata` only when you are intentionally sending sensitive data to the caller. The
`replacement-db list` command also has `--include-values` for explicitly inspecting candidate and assignment values.

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

Other public helpers include `anonymize_text`, `anonymize_file`, `anonymize_config_text`, `anonymize_config_file`,
`deanonymize_text`, `deanonymize_file`, `apply_bank_patches`, `bank_stats`, `benchmark_bank`, `canonicalize_bank`,
`diff_banks`, `eval_bank`, `extract_batch`, `extract_file`, `extract_report`, `explain_match`, `hash_bank`,
`regress_bank`, and `validate_bank_schema`.

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
benchmarking, regression, stats, match explanation, replacement DB validation/save, anonymization, and
de-anonymization. Config-backed extraction and config-backed anonymization tools are also available for YAML detector
configs.

MCP anonymization tools:

- `create_replacement_db`
- `validate_replacement_db`
- `save_replacement_db`
- `anonymize_text`
- `anonymize_file`
- `anonymize_config_text`
- `anonymize_config_file`
- `deanonymize_text`
- `deanonymize_file`

MCP writes are explicit: `create_replacement_db` does not write files; `save_replacement_db` writes only to
`save_db_path`; anonymize tools save DB changes only when `options.save` is true and `save_db_path` is provided. Reading
from `replacement_db_path` never implies an in-place save.

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

## Security Notes

NERB pseudonymization is deterministic replacement, not cryptographic anonymization. A pseudonym can still be identifying
through context, frequency, or an exposed replacement database. Treat reversible DBs as sensitive local files, especially
when `store_originals` is true. `store_originals=false` supports stable future replacement but cannot de-anonymize back
to originals.

De-anonymization restores redaction tokens by default. Pseudonym restoration is opt-in because it is exact string
replacement: if the pseudonym also appears naturally in transformed text, that natural occurrence may be restored too.

## Performance

NERB uses Python as the authoring and control plane, and Rust as the matching data plane. Literal and regex patterns are
canonicalized into Rust detector metadata, scanned natively, then projected into stable JSON records. Compiled banks are
cached in process by canonical bank hash, engine version, compile options, and platform dimensions.

The final Rust engine gate covers conformance, dense memory, mode strategy, wheel smoke tests, and a representative
synthetic medium bank with 1,000 entities. See [`docs/performance.md`](docs/performance.md) for the current performance
summary and [`docs/rust-engine-gates.md`](docs/rust-engine-gates.md) for recorded release-gate evidence.

For large-source bank construction, see the Enron-backed benchmark guide in
[`docs/enron-benchmark.md`](docs/enron-benchmark.md) and the measured optimization harness in
[`docs/autoresearch.md`](docs/autoresearch.md). Agent workflows can also use the reusable
[`nerb-large-source-bank-building`](.agents/skills/nerb-large-source-bank-building/SKILL.md) skill for corpus profiling
and privacy-safe handoff guidance.

## Development

```shell
make sync
make check
make build
```

`make check` runs Ruff linting and formatting checks, `mypy src/nerb`, `ty check`, pytest, and Rust crate tests.
`make build` builds and validates the source distribution plus the local platform wheel with `twine check --strict`.

# Named Entity Regex Builder (NERB)

[![CI](https://github.com/johnnygreco/nerb/actions/workflows/tests.yml/badge.svg)](https://github.com/johnnygreco/nerb/actions/workflows/tests.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/johnnygreco/nerb/blob/main/LICENSE)

NERB builds, validates, extracts, reports, evaluates, diffs, and benchmarks named-entity regex banks. The current
agent-first surface uses JSON banks and returns JSON-compatible facts for local tools, CI gates, and MCP clients. The
older YAML detector-config workflow is still available for simple regex extraction and authoring.

## Installation

```shell
pip install --upgrade nerb
nerb --help
```

From a source checkout:

```shell
git clone https://github.com/johnnygreco/nerb.git
cd nerb
uv sync --all-extras
uv run nerb --help
```

The current package targets Python 3.10 and newer. The `nerb-mcp` entry point also requires Python 3.10 or newer because
it uses the official MCP SDK.

## JSON Banks

A JSON bank is the agent-first format. It stores entities, canonical names, pattern metadata, statuses, eval references,
and literal or regex pattern settings in one validated object.

```json
{
  "schema_version": "nerb.bank.v1",
  "id": "company_entities",
  "name": "Company Entities",
  "description": "Known private entities for agent workflows.",
  "version": "2026.06.03",
  "status": "active",
  "created_at": "2026-06-03T00:00:00Z",
  "updated_at": "2026-06-03T00:00:00Z",
  "unicode_normalization": "none",
  "default_regex_flags": ["IGNORECASE"],
  "entities": {
    "customer": {
      "description": "Customer organizations and accounts.",
      "status": "active",
      "regex_flags": [],
      "names": {
        "acme_corp": {
          "canonical": "Acme Corp",
          "description": "Strategic customer account.",
          "status": "active",
          "patterns": {
            "primary": {
              "kind": "literal",
              "value": "Acme Corp",
              "description": "Exact Acme Corp alias.",
              "status": "active",
              "priority": 100,
              "case_sensitive": false,
              "normalize_whitespace": true,
              "left_boundary": "word",
              "right_boundary": "word",
              "metadata": {}
            }
          },
          "metadata": {}
        }
      },
      "metadata": {}
    }
  },
  "metadata": {}
}
```

## CLI Quickstart

JSON-bank commands emit JSON matching the Python helper response shape.

```shell
nerb validate-bank --bank company.json
nerb extract-text --bank company.json --text "Send this to Acme Corp today."
nerb extract-file --bank company.json --file email.txt
nerb extract-report --bank company.json --file email.txt
nerb eval-bank --bank company.json
nerb benchmark-bank --bank company.json
```

Extraction records include stable core fields (`entity`, `name`, `string`, `start`, `end`) plus JSON-bank IDs, pattern
kind, and captures:

```json
{
  "entity": "customer",
  "entity_id": "customer",
  "name": "Acme Corp",
  "name_id": "acme_corp",
  "pattern_id": "primary",
  "pattern_kind": "literal",
  "string": "Acme Corp",
  "start": 13,
  "end": 22,
  "captures": {}
}
```

Agent repair and promotion workflows use the same helper surfaces:

```shell
nerb apply-patches --bank company.json --patch patches.json
nerb diff-banks old-company.json new-company.json
nerb regress-bank --old-bank old-company.json --new-bank new-company.json
```

`apply-patches` applies RFC 6902 JSON Patch operations before validation, so a patch can repair an invalid bank and
return the validated candidate plus diagnostics.

## Python API

Use the JSON-bank helpers when building agent or service integrations:

```python
from nerb import (
    apply_bank_patches,
    benchmark_bank,
    diff_banks,
    eval_bank,
    extract_report,
    extract_text,
    load_bank,
    regress_bank,
    validate_bank,
)

bank = load_bank("company.json")

validation = validate_bank(bank)
extraction = extract_text(bank, "Send this to Acme Corp today.")
report = extract_report(bank, "Send this to Acme Corp today.")
benchmark = benchmark_bank(bank, options={"benchmark_iterations": 1})
```

Other public helpers include `Bank`, `bank_stats`, `bank_cache_info`, `canonicalize_bank`, `clear_bank_cache`,
`hash_bank`, `validate_bank_schema`, `benchmark_fixture_profiles`, `make_benchmark_fixture_profile`, `extract_file`,
`extract_batch`, `extract_report_file`, `extract_report_batch`, `explain_match`, and `compiled_bank_cache_info`.

The Rust engine migration is underway. Native source-bank canonicalization is documented in
[`docs/rust-engine-canonicalization.md`](docs/rust-engine-canonicalization.md), and the current native PyO3 boundary plus
`entity_independent` `scan_bytes` path are documented in
[`docs/rust-engine-boundary.md`](docs/rust-engine-boundary.md). The current Python `NERB` API remains only until the
Rust-backed `Bank` surface replaces it.

The current Python regex-builder API is still present until the Rust-backed `Bank` API replaces it:

```python
from pathlib import Path

from nerb import NERB

config_path = Path("examples/music_entities.yaml")
document = Path("examples/prog_rock_wiki.txt").read_text(encoding="utf-8")

extractor = NERB(config_path, add_word_boundaries=True)
records = extractor.extract_named_entities(document).to_records()
```

Compiled entity regexes are exposed today as attributes such as `extractor.ARTIST`.

## Eval And Regression

Eval references are local JSONL files attached at the bank, entity, name, or pattern level through `eval_refs`. Positive
records assert exact expected matches, negative records assert that scoped extraction returns no matches, and provenance
records are counted without affecting pass/fail.

`regress_bank` runs:

```text
diff_banks -> eval old/new -> benchmark old/new -> quality and performance deltas
```

Regression output is machine-readable for external promotion gates. NERB does not own publishing, approval, signing,
scheduling, deployment, or disk cache behavior.

## MCP Server

Run the local stdio MCP server from the repo:

```shell
uv run nerb-mcp
```

Minimal MCP client config:

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

JSON-bank MCP tools:

```text
validate_bank
apply_bank_patches
diff_banks
bank_stats
extract_text
extract_file
extract_batch
extract_report
extract_report_batch
eval_bank
benchmark_bank
explain_match
regress_bank
```

Rust/config-backed MCP tools:

```text
validate_config
load_config
list_detectors
add_detector
update_detector
remove_detector
extract_entity
extract_all_entities
extract_inline
engine_cache_info
clear_engine_cache
```

JSON-bank MCP tools accept explicit bank objects or explicit bank paths, depending on the tool. Rust/config-backed tools
accept explicit config paths, provided inline detector definitions, and explicit document paths or text. File reads are
limited to explicit bank, config, document, patch, and eval paths; config writes are limited to the explicit
`config_path` passed by the client.

## YAML Detector Configs

The YAML detector-config workflow is useful for simple regex extraction and authoring.

```yaml
ARTIST:
  Pink Floyd: 'Pink\sFloyd'
  The Who: '[Tt]he\sWho'

GENRE:
  _flags: IGNORECASE
  Rock: '(?:progressive\s)?rock'
```

Config path resolution:

1. explicit `--config`
2. `NERB_CONFIG_PATH`
3. the platform user config path

Common commands:

```shell
nerb init --config detectors.yaml
nerb add ARTIST "Pink Floyd" 'Pink\sFloyd' --config detectors.yaml
nerb extract ARTIST examples/prog_rock_wiki.txt --config detectors.yaml --format json
nerb extract-batch examples/prog_rock_wiki.txt examples/other.txt --entity ARTIST --config detectors.yaml --format json
nerb extract --all --text "Pink Floyd played progressive rock." \
  --detector 'ARTIST:Pink Floyd=Pink\sFloyd' \
  --detector 'GENRE:Rock=rock' \
  --format json
nerb test ARTIST "Pink Floyd" 'Pink\sFloyd' --text "Pink Floyd played progressive rock."
nerb compile ARTIST --config detectors.yaml
nerb doctor --config detectors.yaml --format json
```

YAML extraction supports `--format table`, `--format json`, and `--format jsonl`. JSON and JSONL records are
Rust-backed byte-offset records with `entity`, `canonical_name`, `surface_name`, `string`, `start`, `end`, and
`offset_unit`. `extract-batch` accepts explicit document paths, `--manifest` path lists, and one optional `--stdin`
document; it compiles one Rust `Bank` and scans those documents in input order.

## Performance

NERB compiles one Python `re` shard per entity for regex patterns, uses separate literal shards for literal patterns,
caches compiled banks in process by canonical bank hash and extraction options, and keeps disk cache deferred for V1.

See [docs/performance.md](docs/performance.md) for target/stress benchmark commands and recorded results. The V1 review
keeps PCRE2 optional and does not add a binary literal-matcher dependency.

## Development

```shell
make sync
make check
make build
```

`make check` runs Ruff linting and formatting checks, `mypy src/nerb`, `ty check`, and pytest.

---
icon: lucide/terminal-square
description: "Use the same NERB bank through CLI commands, Python helpers, and MCP tools."
---

# Interfaces

NERB exposes the same extraction behavior through a shell CLI, Python helpers, and a local stdio MCP server. Use the
surface that matches the caller, and keep shared behavior in the bank itself.

## Equivalent Extraction Paths

=== "CLI"

    ```shell
    nerb extract-text --bank company.json --text "Send this to Acme Corp today."
    nerb extract-file --bank company.json --file email.txt
    nerb extract-report --bank company.json --file email.txt
    ```

=== "Python"

    ```python
    from nerb import extract_file, extract_report, extract_text, load_bank

    bank = load_bank("company.json")
    result = extract_text(bank, "Send this to Acme Corp today.")
    file_result = extract_file(bank, "email.txt")
    report = extract_report(bank, "email.txt")
    ```

=== "MCP"

    ```json
    {
      "mcpServers": {
        "nerb": {
          "command": "nerb-mcp"
        }
      }
    }
    ```

## CLI

The CLI is the best surface for CI, local bank authoring, and shell-driven reports:

```shell
nerb validate-bank --bank company.json
nerb diff-banks old-company.json new-company.json
nerb regress-bank --old-bank old-company.json --new-bank new-company.json
```

Config-backed YAML detector commands are also available for compact regex detector authoring:

```shell
nerb init --config detectors.yaml
nerb add ARTIST "Pink Floyd" 'Pink\sFloyd' --config detectors.yaml
nerb extract --all --text "Pink Floyd played progressive rock." --config detectors.yaml --format json
```

## Python API

Use JSON-bank helpers for agent, service, and test integrations:

```python
from nerb import benchmark_bank, extract_text, load_bank, validate_bank

bank = load_bank("company.json")
assert validate_bank(bank)["valid"]
records = extract_text(bank, "Acme Corp renewed.")["records"]
timings = benchmark_bank(bank)
```

Use `Bank` directly when you want the Rust-backed source-bank API:

```python
from nerb import Bank

bank = Bank.from_source_bytes(b'{"CODE":{"Alpha":"Alpha"}}', format_hint="json")
records = bank.scan_text("Alpha")
```

## MCP Server

Run the local stdio server:

```shell
nerb-mcp --version
```

From a source checkout:

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

MCP tools read explicit config/document paths or provided text. Write tools require explicit output paths, and extraction
tools read exactly one source: provided `text` or an explicit document `file_path`.

## Record Contract

Rust-backed records include:

| Field | Meaning |
| --- | --- |
| `entity` | Entity ID or source entity name |
| `canonical_name` | Canonical entity label |
| `surface_name` | Surface alias for the matched detector |
| `string` | Matched document substring |
| `start`, `end` | Start and exclusive end offsets |
| `offset_unit` | Usually `byte` |

JSON-bank extraction enriches records with `entity_id`, `name_id`, `pattern_id`, `pattern_kind`, and `captures`.

---
icon: lucide/play
description: "Install NERB, create a minimal bank, validate it, extract records, and call the Python API."
---

# Quickstart

## Install

```shell
pip install --upgrade nerb
nerb --help
```

NERB requires Python 3.10 or newer. Published releases include CPython 3.10 through 3.14 wheels for Linux x86_64,
macOS universal2, and Windows x86_64.

From a source checkout:

```shell
git clone https://github.com/johnnygreco/nerb.git
cd nerb
make sync
uv run nerb --help
```

## Save A Bank

Create `company.json`:

```json title="company.json"
{
  "schema_version": "nerb.bank.v1",
  "id": "company_entities",
  "name": "Company Entities",
  "description": "Companies to recognize in internal documents.",
  "version": "2026.06.24",
  "status": "active",
  "created_at": "2026-06-24T00:00:00Z",
  "updated_at": "2026-06-24T00:00:00Z",
  "unicode_normalization": "none",
  "default_regex_flags": ["IGNORECASE"],
  "entities": {
    "company": {
      "description": "Organizations.",
      "status": "active",
      "regex_flags": [],
      "names": {
        "acme_corp": {
          "canonical": "Acme Corp",
          "description": "Primary account.",
          "status": "active",
          "patterns": {
            "primary": {
              "kind": "literal",
              "value": "Acme Corp",
              "description": "Exact company alias.",
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

Then validate it:

```shell
nerb validate-bank --bank company.json
```

A valid bank is ready for extraction. Invalid banks return diagnostics before any scan is attempted. See
[Schema Reference](schemas.md#minimal-complete-bank) for the full bank contract.

## Extract From Text

```shell
nerb extract-text \
  --bank company.json \
  --text "Send this to Acme Corp today."
```

The response includes a record like:

```json
{
  "records": [
    {
      "entity": "company",
      "canonical_name": "Acme Corp",
      "surface_name": "Acme Corp",
      "string": "Acme Corp",
      "start": 13,
      "end": 22,
      "offset_unit": "byte",
      "entity_id": "company",
      "name_id": "acme_corp",
      "pattern_id": "primary",
      "pattern_kind": "literal",
      "captures": {}
    }
  ]
}
```

For a file:

```shell
nerb extract-text --bank company.json --file email.txt
nerb extract-file --bank company.json --file email.txt
nerb extract-report --bank company.json --file email.txt
```

`extract-text` accepts `--text`, `--stdin`, or `--file`; `extract-file` is the explicit file-only equivalent. Both
return JSON extraction responses. `extract-report` applies report-oriented overlap resolution and summary metadata.

## Use Python

```python
from nerb import extract_text, load_bank, validate_bank

bank = load_bank("company.json")
validation = validate_bank(bank)
result = extract_text(bank, "Send this to Acme Corp today.")
file_result = extract_text(bank, file_path="email.txt")

assert validation["valid"]
print(result["records"])
print(file_result["records"])
```

For direct Rust-backed source-bank scans:

```python
from nerb import Bank

bank = Bank.from_source_bytes(b'{"ARTIST":{"Rush":"Rush"}}', format_hint="json")
records = bank.scan_text("Rush played in Toronto.")
```

## Use MCP From An Agent

After installing NERB, point MCP clients at the local stdio server:

```json
{
  "mcpServers": {
    "nerb": {
      "command": "nerb-mcp"
    }
  }
}
```

From a source checkout, use `command: "uv"`, `args: ["run", "nerb-mcp"]`, and set `cwd` to the repo root. MCP tools use
the same bank validation and extraction contracts; tools read explicit paths or provided text, and write tools require
explicit output paths.

## Add A Promotion Gate

Once a bank has eval references, use the promotion commands before merging bank changes:

```shell
nerb diff-banks old-company.json new-company.json
nerb eval-bank --bank new-company.json
nerb benchmark-bank --bank new-company.json
nerb regress-bank \
  --old-bank old-company.json \
  --new-bank new-company.json
```

`regress-bank` combines diff, eval, and benchmark checks into one machine-readable response.

## Next

- [Workflows](workflows.md) for the bank lifecycle.
- [Interfaces](interfaces.md) for CLI, Python, and MCP usage.
- [Anonymization](anonymization.md) for redaction and pseudonym replacement.
- [Schema Reference](schemas.md) for the complete JSON contracts.

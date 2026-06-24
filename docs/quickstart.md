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

Copy the minimal bank from [Schema Reference](schemas.md#minimal-complete-bank) into `company.json`, then validate it:

```shell
nerb validate-bank --bank company.json
```

A valid bank is ready for extraction. Invalid banks return diagnostics before any scan is attempted.

## Extract From Text

```shell
nerb extract-text --bank company.json --text "Send this to Acme Corp today."
```

For a file:

```shell
nerb extract-file --bank company.json --file email.txt
nerb extract-report --bank company.json --file email.txt
```

`extract-text` and `extract-file` return JSON extraction responses. `extract-report` applies report-oriented overlap
resolution and summary metadata.

## Use Python

```python
from nerb import extract_text, load_bank, validate_bank

bank = load_bank("company.json")
validation = validate_bank(bank)
result = extract_text(bank, "Send this to Acme Corp today.")

assert validation["valid"]
print(result["records"])
```

For direct Rust-backed source-bank scans:

```python
from nerb import Bank

bank = Bank.from_source_bytes(b'{"ARTIST":{"Rush":"Rush"}}', format_hint="json")
records = bank.scan_text("Rush played in Toronto.")
```

## Add A Promotion Gate

Once a bank has eval references, use the promotion commands before merging bank changes:

```shell
nerb diff-banks old-company.json new-company.json
nerb eval-bank --bank new-company.json
nerb benchmark-bank --bank new-company.json
nerb regress-bank --old-bank old-company.json --new-bank new-company.json
```

`regress-bank` combines diff, eval, and benchmark checks into one machine-readable response.

## Next

- [Workflows](workflows.md) for the bank lifecycle.
- [Interfaces](interfaces.md) for CLI, Python, and MCP usage.
- [Anonymization](anonymization.md) for redaction and pseudonym replacement.
- [Schema Reference](schemas.md) for the complete JSON contracts.

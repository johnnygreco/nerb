# Agent Guide

This guide is for coding agents working in NERB. Keep changes small, verify them with the Makefile or uv commands below, and prefer core helpers over duplicated CLI or MCP logic.

## Project Layout

- `src/nerb/regex_builder.py`: `NERB`, compiled regex construction, and current Python regex-builder methods.
- `src/nerb/config.py`: detector config loading, validation, default path resolution, and atomic YAML saves.
- `src/nerb/extraction.py`: reusable extraction helpers and record serialization helpers.
- `src/nerb/named_entities.py`: `NamedEntity` and `NamedEntityList` public data structures.
- `src/nerb/cli.py`: Typer CLI for config commands.
- `tests/nerb/`: unit tests for the public API, CLI behavior, config validation, and extraction output.
- `examples/`: README example inputs.
- `docs/releasing.md`: release and publishing process.
- `.agents/skills/`: focused reusable instructions for recurring agent work.

## Local Setup

Use uv through the Makefile when possible:

```shell
make sync
```

Equivalent direct command:

```shell
uv sync --all-extras
```

The installed console scripts are `nerb` and, on Python 3.10+, `nerb-mcp`. Current CLI commands are `extract`, `init`,
`add`, `list`, `show`, `remove`, and `validate`.

## Verification

Run the broad check before a PR when practical:

```shell
make check
```

Targeted commands:

```shell
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run ty check
make build
```

`make check` runs Ruff lint/format checks, `mypy src/nerb`, `ty check`, and pytest. `make build` builds and validates distributions with twine. For release changes, follow `docs/releasing.md`.

## Development Rules

- During the Rust engine migration, treat the Rust-backed `Bank` API as the target. Do not add shims for current Python regex-builder callers unless an active issue explicitly requires one.
- Put shared behavior in `config.py`, `extraction.py`, `named_entities.py`, or `regex_builder.py`; have CLI and future MCP code call those helpers instead of reimplementing parsing, validation, or serialization.
- Current Python oracle records keep JSON-compatible fields: `entity`, `name`, `string`, `start`, and `end`.
  New Rust-backed `Bank` scan records follow the explicit Rust record contract in
  `docs/decisions/0001-rust-engine-semantics.md`.
- Maintain deterministic behavior. Current Python oracle extraction sorts by start offset, end offset, entity, name,
  and matched string; Rust-backed `Bank` scan ordering follows `docs/decisions/0001-rust-engine-semantics.md`.
- Keep user-facing CLI behavior covered with `typer.testing.CliRunner` tests in `tests/nerb/test_cli.py`.
- Respect configured tooling in `pyproject.toml`: Ruff line length is 120 and CI runs Python 3.10 and 3.13.
- Do not broaden filesystem side effects. Config writes should stay explicit and atomic through `save_config`.

## MCP Server

Launch the local stdio MCP server from the repo with:

```shell
uv run nerb-mcp
```

Minimal local MCP client config:

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

MCP config tools read only the explicit `config_path` passed by the client. Config write tools require `config_path` and
save atomically through `save_config`. Extraction tools read exactly one source, either provided `text` or an explicit
document `file_path`. `extract_inline` uses provided detector definitions and does not read or write a config file. If
`nerb-mcp` is invoked on Python versions unsupported by the MCP SDK, it exits with a clear compatibility error.

## Common Pitfalls

- `NERB_CONFIG_PATH` overrides the platform default config path; explicit `--config` or function arguments take precedence.
- Empty top-level configs are valid, but every non-empty entity must have at least one pattern.
- `_flags` is reserved for regex flags and cannot be used as a detector pattern name.
- Pattern names are converted from spaces to underscores for regex group names; invalid group names must fail validation.
- MCP support uses the official Python MCP SDK, which currently requires Python 3.10 or newer.

## Reusable Skills

Use these when the task matches:

- `.agents/skills/nerb-cli-config/SKILL.md`: CLI commands and detector config behavior.
- `.agents/skills/nerb-extraction-surfaces/SKILL.md`: extraction behavior, records, and public extraction surfaces.
- `.agents/skills/nerb-mcp-tools/SKILL.md`: MCP tool implementation and launch/test workflow.
- `.agents/skills/nerb-release-publishing/SKILL.md`: release, build, and publishing workflow changes.

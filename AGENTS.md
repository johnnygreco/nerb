# Agent Guide

This guide is for coding agents working in NERB. Keep changes small, verify them with the Makefile or uv commands below, and prefer core helpers over duplicated CLI or MCP logic.

## Project Layout

- `src/nerb/regex_builder.py`: `NERB`, compiled regex construction, and legacy Python API methods.
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

The installed console script is `nerb`. Current CLI commands are `init`, `add`, `list`, `show`, `remove`, and `validate`.

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

- Preserve the Python API while making CLI and MCP surfaces first-class. Keep `NERB`, `NamedEntity`, `NamedEntityList`, config helpers, extraction helpers, and exports in `src/nerb/__init__.py` stable unless a task explicitly requires a breaking change.
- Put shared behavior in `config.py`, `extraction.py`, `named_entities.py`, or `regex_builder.py`; have CLI and future MCP code call those helpers instead of reimplementing parsing, validation, or serialization.
- Keep output records JSON-compatible with stable fields: `entity`, `name`, `string`, `start`, and `end`.
- Maintain deterministic behavior. Extraction across all entities sorts by start offset, end offset, entity, name, and matched string.
- Keep user-facing CLI behavior covered with `typer.testing.CliRunner` tests in `tests/nerb/test_cli.py`.
- Respect configured tooling in `pyproject.toml`: Ruff line length is 120 and CI runs Python 3.8 and 3.13.
- Do not broaden filesystem side effects. Config writes should stay explicit and atomic through `save_config`.

## Common Pitfalls

- `NERB_CONFIG_PATH` overrides the platform default config path; explicit `--config` or function arguments take precedence.
- Empty top-level configs are valid, but every non-empty entity must have at least one pattern.
- `_flags` is reserved for regex flags and cannot be used as a detector pattern name.
- Pattern names are converted from spaces to underscores for regex group names; invalid group names must fail validation.
- CLI extraction commands are not present on `main` yet. Do not document or rely on `nerb extract` until the CLI extraction issue lands.
- MCP support is pending in issue #8. Until `src/nerb/mcp_server.py` and an entry point such as `nerb-mcp` exist, do not treat MCP commands as available. See `.agents/skills/nerb-mcp-tools/SKILL.md` for the planned local workflow.

## Reusable Skills

Use these when the task matches:

- `.agents/skills/nerb-cli-config/SKILL.md`: CLI commands and detector config behavior.
- `.agents/skills/nerb-extraction-surfaces/SKILL.md`: extraction behavior, records, and public API compatibility.
- `.agents/skills/nerb-mcp-tools/SKILL.md`: pending MCP tool implementation and launch/test workflow.
- `.agents/skills/nerb-release-publishing/SKILL.md`: release, build, and publishing workflow changes.

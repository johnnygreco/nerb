---
name: nerb-mcp-tools
description: Use when implementing, testing, or documenting NERB Model Context Protocol tools and local MCP client launch workflows.
---

# NERB MCP Tools

NERB exposes a local MCP server through `src/nerb/mcp_server.py` and the `nerb-mcp` console entry point on Python 3.10
and newer. The current package targets Python 3.10 and newer, matching the official Python MCP SDK's floor.

## Rust Engine Plan Precedence

When working on tracker #45 or `agent-scratchpads/rust-engine-plan.md`, that plan and the active implementation issue
override current MCP/Python helper guidance in this skill. New Rust-backed MCP extraction records follow the explicit
Rust record contract instead of the current Python oracle shape unless the active issue says otherwise.

## Surface

MCP tools wrap the same helpers used by the Python API and CLI:

- validate/load detector configs through `src/nerb/config.py`
- add, update, remove, and list detector patterns through config helpers
- extract one entity or all entities through `src/nerb/extraction.py`
- support one-shot inline extraction without requiring a saved config
- current Python oracle extraction returns JSON-compatible data with `entity`, `name`, `string`, `start`, and `end`

Avoid broad filesystem access. Tools read only explicit config/document paths or provided text, and writes go through
explicit config paths. On Python versions unsupported by the MCP SDK, `nerb-mcp` exits with a clear compatibility error.

## Local Workflow

Launch the stdio server locally with:

```shell
uv run nerb-mcp
```

The module command also works:

```shell
uv run python -m nerb.mcp_server
```

Minimal local MCP client config after the entry point exists:

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

## Acceptance Checks

```shell
uv run pytest tests/nerb/test_mcp*.py
uv run pytest tests/nerb/test_extraction.py
uv run ty check
make check
```

MCP extraction results should match the Python extraction helpers for `tests/data/music_entities.yaml` and `tests/data/prog_rock_wiki.txt`.

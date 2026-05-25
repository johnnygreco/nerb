---
name: nerb-mcp-tools
description: Use when implementing, testing, or documenting NERB Model Context Protocol tools and local MCP client launch workflows.
---

# NERB MCP Tools

MCP support is pending in issue #8. On current `main`, there is no `src/nerb/mcp_server.py`, no `nerb-mcp` entry point, and no MCP test module. Do not claim MCP commands are available until those files land.

## Planned Surface

When issue #8 lands, MCP tools should wrap the same helpers used by the Python API and CLI:

- validate/load detector configs through `src/nerb/config.py`
- add, update, remove, list, and show detector patterns through config helpers
- extract one entity or all entities through `src/nerb/extraction.py`
- support one-shot inline extraction without requiring a saved config
- return JSON-compatible data with `entity`, `name`, `string`, `start`, and `end`

Avoid broad filesystem access. Tools should read only explicit config/document paths or provided text, and writes should go through explicit config paths.

## Pending Local Workflow

Before #8 lands, verify the implementation is still absent with:

```shell
rg -n "mcp|nerb-mcp" pyproject.toml src tests README.md
```

After #8 lands, use the launch command documented by that implementation. The planned command from issue #8 is:

```shell
uv run nerb-mcp
```

If the implementation chooses a module command instead, use:

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

## Acceptance Checks After #8

```shell
uv run pytest tests/nerb/test_mcp*.py
uv run pytest tests/nerb/test_extraction.py
uv run ty check
make check
```

MCP extraction results should match the Python extraction helpers for `tests/data/music_entities.yaml` and `tests/data/prog_rock_wiki.txt`.

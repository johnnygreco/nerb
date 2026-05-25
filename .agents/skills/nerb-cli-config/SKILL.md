---
name: nerb-cli-config
description: Use when adding or changing NERB CLI detector config commands, config path resolution, YAML validation, or config mutation behavior.
---

# NERB CLI and Config

Use this skill for config-focused CLI work. Keep CLI behavior thin and put reusable rules in `src/nerb/config.py`.

## Files

- `src/nerb/cli.py`: Typer app and command output.
- `src/nerb/config.py`: canonical config schema, validation, path resolution, and persistence.
- `tests/nerb/test_cli.py`: CLI command behavior.
- `tests/nerb/test_config.py`: config helper behavior.

## Current CLI Surface

Available commands:

```shell
uv run nerb init --config detectors.yaml
uv run nerb add ARTIST "Pink Floyd" "Pink\\sFloyd" --config detectors.yaml
uv run nerb list --config detectors.yaml
uv run nerb show ARTIST --config detectors.yaml
uv run nerb remove ARTIST "Pink Floyd" --config detectors.yaml
uv run nerb validate --config detectors.yaml
```

Config path precedence is explicit `--config` or function argument, then `NERB_CONFIG_PATH`, then the platform user config path.

## Implementation Guidance

- Reuse `load_config`, `save_config`, `validate_pattern_config`, `add_entity_pattern`, and `remove_entity_pattern`.
- Keep command errors deterministic and include the config path when it helps the user fix the problem.
- Use `ConfigError` for validation failures in core helpers; convert those to CLI exit code `1` in `cli.py`.
- Preserve atomic writes through `save_config`; do not write YAML directly from CLI commands.
- Preserve YAML insertion order. Do not sort detector names unless the task explicitly changes output order.
- Treat `_flags` as the only reserved metadata key in an entity mapping.

## Acceptance Checks

Run focused tests after CLI/config changes:

```shell
uv run pytest tests/nerb/test_cli.py tests/nerb/test_config.py
uv run ruff check .
uv run ty check
```

Use `make check` before opening the PR when practical.

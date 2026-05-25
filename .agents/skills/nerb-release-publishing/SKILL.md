---
name: nerb-release-publishing
description: Use when changing NERB release, build, versioning, PyPI publishing, or GitHub Actions publishing workflows.
---

# NERB Release and Publishing

Use this skill for release workflow changes. Prefer the trusted-publishing GitHub Actions flow documented in `docs/releasing.md`.

## Files

- `docs/releasing.md`: canonical release process.
- `Makefile`: local build, check, and publish targets.
- `pyproject.toml`: package metadata and version.
- `src/nerb/__init__.py`: runtime `__version__`.
- `.github/workflows/tests.yml`: CI checks.
- `.github/workflows/publish.yml`: PyPI publish workflow.

## Commands

```shell
make check
make build
```

Manual publishing targets exist but require explicit confirmation:

```shell
make publish-test CONFIRM=yes
make publish CONFIRM=yes
```

Do not run publish targets unless the user explicitly asks for a publish operation.

## Implementation Guidance

- Keep `pyproject.toml` version and `src/nerb/__init__.py` `__version__` aligned.
- Keep release docs and workflow names in sync.
- Preserve the trusted-publisher setup: owner `johnnygreco`, repository `nerb`, workflow `publish.yml`, environment `pypi`.
- Prefer `make build` for local distribution validation; it runs `uv build --clear` and strict `twine check`.
- Keep CI PR-safe. Publishing should remain release-triggered or manually dispatched, not run on pull requests.

## Acceptance Checks

```shell
make check
make build
```

For documentation-only release changes, still verify referenced commands and workflow file names exist.

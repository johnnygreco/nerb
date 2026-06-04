# Releasing

NERB publishes to PyPI through the `Publish` GitHub Actions workflow. The workflow is not run for pull requests; it only runs when a GitHub release is published or when a maintainer starts it manually with `workflow_dispatch`.

## Required PyPI setup

Configure a PyPI trusted publisher for the `nerb` project:

- Owner: `johnnygreco`
- Repository: `nerb`
- Workflow filename: `publish.yml`
- Environment name: `pypi`

The workflow uses GitHub OIDC with `id-token: write` and does not require a PyPI API token secret.

## Local build prerequisites

NERB includes a Rust extension built by `maturin`. Local `make build`, source installs, and platform builds that do not
use a prebuilt wheel require a Rust toolchain with `cargo` available on `PATH`. The GitHub Actions test and publish
workflows install Rust before building distributions.

The current publish workflow uploads the source distribution only. PyPI-compatible wheels need an explicit
manylinux/macOS/Windows build matrix and audit/repair step, which is tracked as future distribution work.

## Release steps

1. Update the project version and changelog or release notes as needed.
2. Run `make check`.
3. Run `make build`.
4. Push the release commit and tag.
5. Publish a GitHub release for the tag, or run the `Publish` workflow manually for that tag.

The `make publish-test` and `make publish` targets remain available for manual source-distribution publishing with uv
credentials, but the trusted-publishing workflow is preferred for PyPI releases.

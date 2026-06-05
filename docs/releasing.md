# Releasing

NERB publishes to PyPI through the `Publish` GitHub Actions workflow. The workflow is not run for pull requests; it only runs when a GitHub release is published or when a maintainer starts it manually with `workflow_dispatch`.

## Required PyPI setup

Configure a PyPI trusted publisher for the `nerb` project:

- Owner: `johnnygreco`
- Repository: `nerb`
- Workflow filename: `publish.yml`
- Environment name: `release`

The workflow uses GitHub OIDC with `id-token: write` and does not require a PyPI API token secret.

## Supported wheel matrix

Published releases include:

- source distribution: `nerb-<version>.tar.gz`;
- Linux x86_64 wheels tagged `manylinux_2_28`;
- macOS universal2 wheels supporting x86_64 and arm64;
- Windows x86_64 wheels.

The wheel workflow builds CPython 3.10, 3.11, 3.12, 3.13, and 3.14 wheels for each supported platform above. Platforms
outside this matrix install from the source distribution and require a Rust toolchain.

CI and the publish workflow smoke-test the produced wheels in fresh Python environments without setting up Rust by
installing the wheel artifact and running a minimal `nerb.Bank` native scan. The macOS universal2 artifact is
install-smoked on both macOS arm64 and Intel runners.

## Local build prerequisites

NERB includes a Rust extension built by `maturin`. Local `make build`, source installs, and platform builds that do not
use a prebuilt wheel require a Rust toolchain with `cargo` available on `PATH`. The GitHub Actions test and publish
workflows install Rust before building distributions.

The GitHub Actions publish workflow builds the source distribution, platform wheels, verifies all artifacts with
`twine check --strict`, and publishes the complete `dist/` directory through PyPI trusted publishing.

## Release steps

1. Update the project version and changelog or release notes as needed.
2. Run `make check`.
3. Run `make build`.
4. Push the release commit and tag.
5. Confirm the CI wheel matrix is green on the release commit.
6. Publish a GitHub release for the tag, or run the `Publish` workflow manually for that tag.

The `make publish-test` and `make publish` targets remain available for manual source-distribution publishing with uv
credentials, but the trusted-publishing workflow is preferred for PyPI releases.

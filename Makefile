UV ?= uv

.DEFAULT_GOAL := help

.PHONY: help sync format lint type test rust-test check build build-sdist clean publish-test publish

help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*##"; printf "Available targets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

sync: ## Install the project and all optional dependencies with uv.
	$(UV) sync --all-extras

format: ## Format Python code and apply safe Ruff fixes.
	$(UV) run ruff check --fix .
	$(UV) run ruff format .

lint: ## Run Ruff lint and formatting checks.
	$(UV) run ruff check .
	$(UV) run ruff format --check .

type: ## Run static type checks.
	$(UV) run mypy src/nerb
	$(UV) run ty check

test: ## Run the test suite.
	$(UV) run pytest

rust-test: ## Run Rust crate tests without Python extension-module linker settings.
	cargo test --locked --manifest-path rust/Cargo.toml

check: lint type test rust-test ## Run linting, type checks, Python tests, and Rust tests.

build: ## Build and validate source and wheel distributions.
	$(UV) build --clear
	$(UV) run --no-project --with twine twine check --strict dist/*

build-sdist: ## Build and validate the source distribution for publishing.
	$(UV) build --sdist --clear
	$(UV) run --no-project --with twine twine check --strict dist/*.tar.gz

clean: ## Remove local build outputs and tool caches.
	rm -rf build dist .eggs *.egg-info src/*.egg-info
	rm -rf rust/target
	rm -f src/nerb/_engine*.so src/nerb/_engine*.pyd
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage .coverage.* htmlcov
	find . \( -path ./.git -o -path ./.venv \) -prune -o -type d -name __pycache__ -exec rm -rf {} +
	find . \( -path ./.git -o -path ./.venv \) -prune -o -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete

publish-test: ## Manually publish to TestPyPI with uv credentials; requires CONFIRM=yes.
	@if [ "$(CONFIRM)" != "yes" ]; then \
		echo "Refusing to publish to TestPyPI."; \
		echo "Re-run explicitly as: make publish-test CONFIRM=yes"; \
		exit 1; \
	fi
	rm -rf dist
	$(MAKE) build-sdist
	$(UV) publish --publish-url https://test.pypi.org/legacy/ --check-url https://test.pypi.org/simple/ dist/*.tar.gz

publish: ## Manually publish to PyPI with uv credentials; prefer the Publish workflow; requires CONFIRM=yes.
	@if [ "$(CONFIRM)" != "yes" ]; then \
		echo "Refusing to publish to PyPI."; \
		echo "Re-run explicitly as: make publish CONFIRM=yes"; \
		exit 1; \
	fi
	rm -rf dist
	$(MAKE) build-sdist
	$(UV) publish --check-url https://pypi.org/simple/ dist/*.tar.gz

## legionforge-guardian — standalone development commands
##
## Quickstart:
##   make install-dev   # install package + test deps into current venv
##   make test          # run the full test suite
##   make lint          # check formatting
##
## No external services required — all tests are deterministic and in-process.

PYTHON ?= python3

.PHONY: help install-dev test test-checks test-sdk lint format build clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

install-dev: ## Install package + all dev dependencies (pytest, respx, black)
	$(PYTHON) -m pip install -e ".[dev]"

test: ## Run the full test suite (45 tests, <1s, no services required)
	$(PYTHON) -m pytest tests/ -v

test-checks: ## Run only the 7-check enforcement tests (34 tests)
	$(PYTHON) -m pytest tests/test_checks.py -v

test-sdk: ## Run only the SDK client tests (11 tests)
	$(PYTHON) -m pytest tests/test_sdk.py -v

lint: ## Check formatting with Black (no changes)
	$(PYTHON) -m black --check src/ tests/

format: ## Auto-format with Black
	$(PYTHON) -m black src/ tests/

build: ## Build sdist + wheel distributions
	$(PYTHON) -m pip install build --quiet
	$(PYTHON) -m build
	$(PYTHON) -m pip install twine --quiet
	$(PYTHON) -m twine check dist/*

clean: ## Remove build artifacts
	rm -rf dist/ build/ src/legionforge_guardian.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true

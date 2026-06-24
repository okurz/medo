SOURCE_FILES ?= $(shell git ls-files "**.py")
ISOLATE ?= 1

ifeq ($(ISOLATE),1)
UNSHARE := unshare -r -n
else
UNSHARE :=
endif

.PHONY: help
help: ## Display this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: all
all: help

# Detect if pytest-xdist is installed for parallel testing
PYTEST_XDIST := $(shell python3 -c "import xdist" 2>/dev/null && echo "-n auto" || echo "")

.PHONY: test-unit
test-unit: ## Run dynamic tests with coverage report
	$(UNSHARE) python3 -m pytest $(PYTEST_XDIST) --cov --cov-report=xml --cov-report=term-missing

.PHONY: test-unit-no-coverage
test-unit-no-coverage: ## Run dynamic tests without coverage analysis and without style checks
	$(UNSHARE) python3 -m pytest $(PYTEST_XDIST)

.PHONY: only-test-with-coverage
only-test-with-coverage: test-unit  ## Alias for "test-unit"

.PHONY: check-ruff
check-ruff: ## Run ruff linting and formatting checks
	ruff check
	ruff format --check

.PHONY: tidy
tidy: ## Format code and fix linting issues
	ruff format
	ruff check --fix

.PHONY: check-conventions
check-conventions: ## Check for banned coding patterns
	@if git grep -nE '^\s*@(unittest\.mock\.|mock\.)?patch' tests/; then \
		echo "Error: @patch decorator detected. Avoid to prevent argument ordering bugs."; \
		echo "   Fix: Use the 'mocker' fixture (pytest-mock) or a 'with patch():' context manager."; \
		exit 1; \
	fi

.PHONY: check-code-health
check-code-health: ## Find dead code (vulture)
	@echo "Checking code health…"
	@vulture ${SOURCE_FILES} --min-confidence 80

.PHONY: check-types-ty
check-types-ty: ## Run ty type checker
	ty check medo

.PHONY: check-types
check-types: check-types-ty

# aggregate targets

.PHONY: checkstyle
checkstyle: ## Run fast style and static analysis checks
	@$(MAKE) -j check-ruff check-conventions check-types

.PHONY: checkstyle-all
checkstyle-all: ## Run all style and static analysis checks
	@$(MAKE) -j checkstyle check-code-health

.PHONY: test
test: ## Run all tests with coverage analysis and style checks
	@$(MAKE) -j test-unit checkstyle-all

.PHONY: test-no-coverage
test-no-coverage: ## Run all tests *without* coverage analysis and style checks (faster)
	@$(MAKE) -j test-unit-no-coverage checkstyle-all

.PHONY: test-with-coverage
test-with-coverage: test  ## Alias for "test"

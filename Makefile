UV_FROZEN = true
export UV_FROZEN

.DEFAULT_GOAL := help

help:  ## Show this help
	@grep -E '^[a-zA-Z_/-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

test:  ## Run unit tests
	uv run pytest tests/unit_tests/ $(TEST_FILE)

integration_test:  ## Run integration tests
	uv run pytest tests/integration_tests/ --timeout 30

lint:  ## Lint code
	uv run ruff check langchain_nono/ tests/

format:  ## Format code
	uv run ruff format langchain_nono/ tests/
	uv run ruff check --fix langchain_nono/ tests/

ci: lint test  ## Run full CI suite

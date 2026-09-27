PYTHON ?= python3

.PHONY: lint test check

lint:
	$(PYTHON) -m ruff check .

test:
	$(PYTHON) -m pytest -q

check: lint test

PYTHON ?= python3
BUILD := build/pyz
PYZ := dist/server-hardening-audit.pyz

.PHONY: lint test check dist clean

lint:
	$(PYTHON) -m ruff check .

test:
	$(PYTHON) -m pytest -q

check: lint test

# Single-file zipapp: package + bundled controls/frameworks/profiles.
dist:
	$(PYTHON) tools/build_pyz.py

clean:
	rm -rf build dist

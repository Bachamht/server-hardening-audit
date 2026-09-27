PYTHON ?= python3
PYZ := dist/server-hardening-audit.pyz

.PHONY: lint test dist redact check clean integration

lint:
	$(PYTHON) -m ruff check .

test:
	$(PYTHON) -m pytest -q

dist:
	$(PYTHON) tools/build_pyz.py

# Redaction gate over anything published from real runs.
redact:
	@if [ -d examples ] && [ -n "$$(ls -A examples 2>/dev/null)" ]; then \
	  $(PYTHON) -m server_hardening_audit redact-check examples; \
	else echo "redact: examples/ is empty, nothing to check"; fi

# Run before every commit: there is no hosted CI.
check: lint test dist redact
	$(PYTHON) $(PYZ) list > /dev/null
	@echo "check: OK"

# Container integration test (needs Docker; do not run on a production host).
# Usage: make integration IMAGE=ubuntu:24.04
IMAGE ?= ubuntu:24.04
integration: dist
	docker run --rm -v "$$PWD:/src:ro" $(IMAGE) bash /src/tests/integration/container.sh

clean:
	rm -rf build dist

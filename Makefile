PYTHON ?= python3

.PHONY: format lint type test build examples secret-scan check clean

format:
	$(PYTHON) -m ruff format --check .

lint:
	$(PYTHON) -m ruff check .

type:
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest

build:
	$(PYTHON) -m build

examples:
	$(PYTHON) -c "from pathlib import Path; from abac_system_tables.config import load_config, loads_verify_config; load_config(Path('examples/config.example.json')); loads_verify_config(Path('examples/verify.example.json').read_text())"

secret-scan:
	$(PYTHON) scripts/secret_scan.py

check: format lint type test build examples secret-scan

clean:
	rm -rf build dist .coverage .pytest_cache .mypy_cache .ruff_cache htmlcov
	find src tests -type d -name __pycache__ -prune -exec rm -rf {} +

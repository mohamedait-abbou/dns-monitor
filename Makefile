.PHONY: help venv install dev demo report test lint format build clean assets docker-demo

VENV ?= .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

help:  ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv:  ## Create the virtual environment
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip

install: venv  ## Install runtime dependencies
	$(PIP) install -r requirements.txt
	$(PIP) install --no-deps -e .

dev: venv  ## Install development dependencies
	$(PIP) install -r requirements-dev.txt
	$(PIP) install --no-deps -e .

demo:  ## Generate a 600-query demo and HTML report
	$(PY) -m dns_monitor run --simulate 600 --seed 7 \
		--jsonl out/events.jsonl --sqlite out/dns.db --html out/report.html \
		--markdown out/report.md --log-file out/alerts.log

report:  ## Re-render reports from out/dns.db
	$(PY) -m dns_monitor report out/dns.db --html out/report.html --markdown out/report.md

test:  ## Run the test suite with coverage
	$(PY) -m pytest --cov=dns_monitor --cov-report=term-missing

lint:  ## Run Ruff
	$(PY) -m ruff check src tests

format:  ## Auto-format with Ruff
	$(PY) -m ruff check --fix src tests

build:  ## Build sdist and wheel
	$(PY) -m build

assets:  ## Regenerate docs images
	$(PY) tools/generate_assets.py

docker-demo:  ## Run the zero-privilege Docker demo
	docker compose -f docker/docker-compose.yml run --rm demo

clean:  ## Remove generated output and caches
	rm -rf out/ build/ dist/ .pytest_cache/ .coverage htmlcov/ *.egg-info/
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

# Contributing

Thanks for improving DNS Monitor!

## Development setup

```bash
git clone https://github.com/mohamedait-abbou/dns-monitor.git
cd dns-monitor
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pre-commit install 2>/dev/null || true   # optional
```

## Workflow

1. Fork and create a topic branch: `git checkout -b feature/my-rule`.
2. Make the change and add tests under `tests/`.
3. Run the checks:

   ```bash
   pytest
   ruff check src tests
   python -m build
   ```

4. Update `README.md`/`docs/` when behaviour or CLI flags change.
5. Open a pull request describing the signal, the false-positive risk and how you tested it.

## Adding a detection rule

- Add the rule ID to `RULES` in `src/dns_monitor/models.py`.
- Add its defaults to `DetectorConfig` in `src/dns_monitor/config.py` and include it in `enabled_rules`.
- Implement a `_xxx_alert()` method in `src/dns_monitor/detector.py` and register it in `evaluate()`.
- Add at least one positive and one negative test in `tests/test_detector.py`.
- Document the rule in `docs/DETECTIONS.md` and the README table.

## Commit style

Use short imperative subjects: `Add entropy rule`, `Fix pcap filter on Windows`, `Document webhook payloads`.

## Code style

- Python 3.10+ syntax, type hints on public functions.
- Line length 110 (Ruff config in `pyproject.toml`).
- No new mandatory runtime dependencies without discussion — prefer the standard library.
- Never commit captures, databases or report output; `.gitignore` covers the usual patterns.

## Reporting bugs

Open an issue with the CLI command, Python/OS version, a minimal reproducer and (if possible) a redacted JSON report.

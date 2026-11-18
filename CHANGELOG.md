# Changelog

All notable changes are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows semantic versioning.

## [1.0.0] - 2026-11-18

### Added

- Installable `src/dns_monitor` package with a `dns-monitor` console script.
- Three input modes: live Scapy capture, PCAP replay and seeded deterministic simulation.
- Eight detection rules: keyword, TLD, entropy, long label, deep subdomain, TXT tunnel, rate limit and NXDOMAIN burst.
- Event sinks for JSONL, CSV and indexed SQLite, plus a `report` command that re-renders from SQLite.
- Console, JSON, Markdown and standalone SVG-based HTML reporters.
- Alert dispatcher with console, log file, generic JSON webhook and Slack payloads.
- YAML/JSON configuration, `DNS_MONITOR_*` environment overrides and CLI overrides.
- Docker image and Compose stack with live-capture capabilities and a no-privilege demo service.
- GitHub Actions CI (tests, Ruff, build), Dependabot, issue templates.
- Generated logo, architecture diagram, dashboard image and terminal screenshot under `docs/images/`.

### Changed

- Replaced the original single-file scripts with a tested package layout; legacy files preserved under `examples/legacy/`.
- Fixed the malformed `requirements.txt` left by an earlier edit.

## [0.1.0] - 2026-05-08

### Added

- Initial `dns-monitor.py` packet sniffer with suspicious keyword and rate-limit alerts.

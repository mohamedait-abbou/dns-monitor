# Usage guide

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .            # runtime only
pip install -r requirements-dev.txt   # tests + lint + build tools
```

## Commands

| Command | Purpose |
| --- | --- |
| `dns-monitor run` | Live capture or `--simulate N` |
| `dns-monitor analyze <pcap>` | Offline capture analysis |
| `dns-monitor report <db>` | Re-render reports from SQLite |
| `dns-monitor rules` | List detection rule IDs and descriptions |
| `dns-monitor --version` | Print version |

### `run`

```bash
dns-monitor run -i eth0 \
  --sqlite out/dns.db \
  --jsonl out/events.jsonl \
  --html out/report.html \
  --markdown out/report.md \
  --webhook-url https://hooks.slack.com/services/XXX \
  --webhook-format slack \
  --min-severity medium
```

| Option | Description |
| --- | --- |
| `-c, --config PATH` | YAML/JSON configuration file |
| `-i, --interface IFACE` | Capture interface; omitted means OS default |
| `--bpf FILTER` | Override the BPF filter |
| `--duration SEC` | Stop after N seconds |
| `--simulate N` | Generate N synthetic queries instead of capturing |
| `--seed N` | Simulation RNG seed (default `7`) |
| `--rate-threshold N` | Queries/window before `rate_limit` fires |
| `--rate-window SEC` | Sliding window length |
| `--entropy-threshold F` | DGA entropy threshold |
| `--nxdomain-threshold N` | NXDOMAIN burst limit |
| `--webhook-url URL` | Alert webhook destination |
| `--webhook-format {generic,slack}` | Payload shape |
| `--min-severity LEVEL` | `info|low|medium|high|critical` |
| `--jsonl/--json/--csv/--sqlite/--html/--markdown PATH` | Output files |
| `--log-file PATH` | Append-only alert log |
| `-q, --quiet` | Suppress per-alert console lines |
| `--no-console-report` | Skip the final text summary |

### `analyze`

```bash
dns-monitor analyze evidence.pcap --html out/pcap.html --csv out/queries.csv
```

### `report`

```bash
dns-monitor report out/dns.db --markdown out/weekly.md
```

## Environment variables

| Variable | Maps to |
| --- | --- |
| `DNS_MONITOR_INTERFACE` | `capture.interface` |
| `DNS_MONITOR_PCAP` | `capture.pcap` |
| `DNS_MONITOR_BPF` | `capture.bpf_filter` |
| `DNS_MONITOR_DURATION` | `capture.duration` |
| `DNS_MONITOR_JSONL` | `output.jsonl` |
| `DNS_MONITOR_JSON` | `output.json` |
| `DNS_MONITOR_SQLITE` | `output.sqlite` |
| `DNS_MONITOR_CSV` | `output.csv` |
| `DNS_MONITOR_HTML` | `output.html` |
| `DNS_MONITOR_MARKDOWN` | `output.markdown` |
| `DNS_MONITOR_LOG_LEVEL` | `output.log_level` |
| `DNS_MONITOR_LOG_FILE` | `output.log_file` |
| `DNS_MONITOR_QUIET` | `output.quiet` |
| `DNS_MONITOR_WEBHOOK_URL` | `alerting.webhook_url` |
| `DNS_MONITOR_WEBHOOK_FORMAT` | `alerting.webhook_format` |
| `DNS_MONITOR_MIN_SEVERITY` | `alerting.min_severity` |
| `DNS_MONITOR_RATE_THRESHOLD` | `detectors.rate_threshold` |
| `DNS_MONITOR_RATE_WINDOW` | `detectors.rate_window` |
| `DNS_MONITOR_ENTROPY_THRESHOLD` | `detectors.entropy_threshold` |

## Privileges

Live capture needs raw-socket access:

```bash
sudo dns-monitor run -i eth0
# or, on Linux:
sudo setcap cap_net_raw,cap_net_admin=eip $(which dns-monitor)
```

Simulation, PCAP analysis and report rendering never require root.

## Webhook payloads

`generic` (default) posts the full alert object:

```json
{
  "timestamp": 1700000000.0,
  "rule": "rate_limit",
  "severity": "high",
  "source_ip": "192.168.1.42",
  "domain": "example.com",
  "message": "55 queries in 60s (limit 50)",
  "metadata": {"count": 55, "window": 60.0}
}
```

`slack` posts `{"text": ":rotating_light: *DNS Monitor HIGH* — …"}`.

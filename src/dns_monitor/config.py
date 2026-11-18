"""Configuration loading with sane defaults and environment overrides."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, get_type_hints

from .utils import ensure_parent

DEFAULT_KEYWORDS = [
    "malware",
    "phishing",
    "botnet",
    "ransomware",
    "c2",
    "command-and-control",
    "exfil",
    "trojan",
    "backdoor",
    "stealer",
]
DEFAULT_TLDS = ["xyz", "top", "su", "cc", "tk", "ml", "ga", "cf", "gq"]


@dataclass
class DetectorConfig:
    enabled_rules: list[str] = field(
        default_factory=lambda: [
            "suspicious_keyword",
            "suspicious_tld",
            "high_entropy",
            "long_label",
            "deep_subdomain",
            "txt_tunnel",
            "rate_limit",
            "nxdomain_burst",
        ]
    )
    suspicious_keywords: list[str] = field(default_factory=lambda: list(DEFAULT_KEYWORDS))
    suspicious_tlds: list[str] = field(default_factory=lambda: list(DEFAULT_TLDS))
    entropy_threshold: float = 3.6
    min_entropy_label_length: int = 10
    max_label_length: int = 40
    max_subdomain_depth: int = 4
    max_txt_answer_length: int = 120
    rate_threshold: int = 50
    rate_window: float = 60.0
    nxdomain_threshold: int = 8
    nxdomain_window: float = 60.0
    ignore_domains: list[str] = field(
        default_factory=lambda: [
            "in-addr.arpa",
            "ip6.arpa",
            "localhost",
            "local",
            "arpa",
        ]
    )


@dataclass
class CaptureConfig:
    interface: str | None = None
    pcap: str | None = None
    bpf_filter: str = "udp port 53 or tcp port 53"
    promiscuous: bool = True
    snaplen: int = 65535
    duration: float | None = None


@dataclass
class OutputConfig:
    jsonl: str | None = None
    json: str | None = None
    sqlite: str | None = None
    csv: str | None = None
    html: str | None = None
    markdown: str | None = None
    log_file: str | None = None
    log_level: str = "INFO"
    quiet: bool = False


@dataclass
class AlertingConfig:
    webhook_url: str | None = None
    webhook_format: str = "generic"  # generic | slack
    min_severity: str = "low"
    webhook_timeout: float = 3.0


@dataclass
class Config:
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    detectors: DetectorConfig = field(default_factory=DetectorConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    alerting: AlertingConfig = field(default_factory=AlertingConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Config:
        data = data or {}
        hints = get_type_hints(cls)
        sections: dict[str, Any] = {}
        for section in fields(cls):
            section_type = hints[section.name]
            raw = data.get(section.name, {}) or {}
            if not isinstance(raw, dict):
                raise ValueError(f"Config section '{section.name}' must be a mapping")
            values = {f.name: raw[f.name] for f in fields(section_type) if f.name in raw}
            sections[section.name] = section_type(**values)
        return cls(**sections)

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        """Load YAML/JSON config, then apply ``DNS_MONITOR_*`` env overrides."""
        data: dict[str, Any] = {}
        if path:
            config_path = Path(path).expanduser()
            text = config_path.read_text(encoding="utf-8")
            if config_path.suffix in {".yaml", ".yml"}:
                try:
                    import yaml
                except ImportError as exc:  # pragma: no cover - optional dependency
                    raise RuntimeError("PyYAML is required for YAML config files") from exc
                data = yaml.safe_load(text) or {}
            else:
                data = json.loads(text)
            if not isinstance(data, dict):
                raise ValueError("Config root must be a mapping")

        config = cls.from_dict(data)
        config.apply_env()
        return config

    def apply_env(self) -> Config:
        """Map env vars such as DNS_MONITOR_INTERFACE onto config fields."""
        mapping = {
            "DNS_MONITOR_INTERFACE": ("capture", "interface"),
            "DNS_MONITOR_PCAP": ("capture", "pcap"),
            "DNS_MONITOR_BPF": ("capture", "bpf_filter"),
            "DNS_MONITOR_DURATION": ("capture", "duration"),
            "DNS_MONITOR_JSONL": ("output", "jsonl"),
            "DNS_MONITOR_JSON": ("output", "json"),
            "DNS_MONITOR_SQLITE": ("output", "sqlite"),
            "DNS_MONITOR_CSV": ("output", "csv"),
            "DNS_MONITOR_HTML": ("output", "html"),
            "DNS_MONITOR_MARKDOWN": ("output", "markdown"),
            "DNS_MONITOR_LOG_LEVEL": ("output", "log_level"),
            "DNS_MONITOR_LOG_FILE": ("output", "log_file"),
            "DNS_MONITOR_QUIET": ("output", "quiet"),
            "DNS_MONITOR_WEBHOOK_URL": ("alerting", "webhook_url"),
            "DNS_MONITOR_WEBHOOK_FORMAT": ("alerting", "webhook_format"),
            "DNS_MONITOR_MIN_SEVERITY": ("alerting", "min_severity"),
            "DNS_MONITOR_RATE_THRESHOLD": ("detectors", "rate_threshold"),
            "DNS_MONITOR_RATE_WINDOW": ("detectors", "rate_window"),
            "DNS_MONITOR_ENTROPY_THRESHOLD": ("detectors", "entropy_threshold"),
        }
        for env_name, (section_name, field_name) in mapping.items():
            if env_name not in os.environ:
                continue
            raw: Any = os.environ[env_name]
            target = getattr(self, section_name)
            current = getattr(target, field_name)
            if isinstance(current, bool):
                value: Any = raw.lower() in {"1", "true", "yes", "on"}
            elif isinstance(current, int) and not isinstance(current, bool):
                value = int(raw)
            elif isinstance(current, float):
                value = float(raw)
            else:
                value = raw
            setattr(target, field_name, value)
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def prepare_paths(self) -> None:
        for path in (
            self.output.jsonl,
            self.output.json,
            self.output.sqlite,
            self.output.csv,
            self.output.html,
            self.output.markdown,
            self.output.log_file,
        ):
            if path:
                ensure_parent(path)


EXAMPLE_CONFIG = """\
# DNS Monitor configuration (YAML or JSON)
capture:
  interface: null          # null = let scapy/OS choose
  bpf_filter: "udp port 53 or tcp port 53"
  promiscuous: true
  duration: null           # e.g. 3600 to stop automatically

detectors:
  rate_threshold: 50
  rate_window: 60
  entropy_threshold: 3.6
  nxdomain_threshold: 8
  suspicious_keywords: [malware, phishing, botnet, c2, exfil]
  suspicious_tlds: [xyz, top, su, tk, ml]

output:
  jsonl: out/events.jsonl
  sqlite: out/dns-monitor.db
  csv: out/queries.csv
  html: out/report.html
  markdown: out/report.md
  log_level: INFO

alerting:
  webhook_url: null        # e.g. https://hooks.slack.com/services/...
  webhook_format: generic  # generic | slack
  min_severity: low
"""

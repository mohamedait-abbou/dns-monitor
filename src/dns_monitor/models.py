"""Typed events produced by the capture layer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class DNSQuery:
    """A single DNS query/response observation."""

    timestamp: float
    source_ip: str
    destination_ip: str
    domain: str
    query_type: str = "A"
    response_code: str = "NOERROR"
    answer: str = ""
    ttl: int | None = None
    protocol: str = "UDP"
    bytes_sent: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DNSQuery:
        allowed = {name for name in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass(frozen=True, slots=True)
class Alert:
    """A detection produced by the rule engine."""

    timestamp: float
    rule: str
    severity: str
    source_ip: str
    domain: str
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        allowed = {name for name in cls.__dataclass_fields__}
        payload = {k: v for k, v in data.items() if k in allowed}
        payload.setdefault("metadata", {})
        return cls(**payload)

    @property
    def title(self) -> str:
        return f"[{self.severity.upper()}] {self.rule}: {self.domain} ({self.source_ip})"


RULES: dict[str, str] = {
    "suspicious_keyword": "Domain contains a risky keyword (malware, phishing, c2, ...)",
    "suspicious_tld": "Domain uses a high-abuse TLD from the configured list",
    "high_entropy": "Label looks algorithmically generated (possible DGA)",
    "long_label": "Unusually long label (possible DNS tunnelling)",
    "deep_subdomain": "Excessive subdomain depth (possible exfiltration)",
    "txt_tunnel": "Oversized TXT/NULL response (possible DNS tunnelling)",
    "rate_limit": "Source IP exceeded the query-rate threshold",
    "nxdomain_burst": "Source IP produced a burst of NXDOMAIN replies",
}

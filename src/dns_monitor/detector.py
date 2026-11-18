"""Rule-based DNS threat detection engine."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from .config import DetectorConfig
from .models import RULES, Alert, DNSQuery
from .utils import (
    domain_labels,
    is_punycode,
    longest_label,
    looks_like_ip,
    shannon_entropy,
    subdomain_depth,
)


class DetectionEngine:
    """Stateless and stateful DNS rules, evaluated for every query.

    Rules can be enabled/disabled through :class:`DetectorConfig`. Stateful
    rules (rate limit, NXDOMAIN burst) keep short sliding windows per source
    IP and use a cooldown to avoid alert storms.
    """

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()
        self._query_times: dict[str, deque[float]] = defaultdict(deque)
        self._nxdomain_times: dict[str, deque[float]] = defaultdict(deque)
        self._cooldowns: dict[tuple[str, str], float] = {}
        self._clock = time.time

    def reset(self) -> None:
        self._query_times.clear()
        self._nxdomain_times.clear()
        self._cooldowns.clear()

    @property
    def enabled_rules(self) -> list[str]:
        return list(self.config.enabled_rules)

    def _rule_on(self, name: str) -> bool:
        return name in self.config.enabled_rules

    def _ignored(self, domain: str) -> bool:
        lowered = domain.lower().rstrip(".")
        return any(
            lowered == ignored.rstrip(".")
            or lowered.endswith("." + ignored.rstrip("."))
            for ignored in self.config.ignore_domains
        )

    def _alert(
        self,
        query: DNSQuery,
        rule: str,
        severity: str,
        message: str,
        metadata: dict | None = None,
        *,
        cooldown: float = 0.0,
    ) -> Alert | None:
        if cooldown:
            key = (rule, query.source_ip)
            now = self._clock()
            last = self._cooldowns.get(key, 0.0)
            if now - last < cooldown:
                return None
            self._cooldowns[key] = now
        return Alert(
            timestamp=query.timestamp,
            rule=rule,
            severity=severity,
            source_ip=query.source_ip,
            domain=query.domain,
            message=message,
            metadata=metadata or {},
        )

    def _keyword_alert(self, query: DNSQuery) -> Alert | None:
        lowered = query.domain.lower()
        labels = domain_labels(query.domain)
        for keyword in self.config.suspicious_keywords:
            needle = keyword.lower().strip(".")
            if not needle:
                continue
            matched = needle in labels if len(needle) <= 3 else needle in lowered
            if matched:
                return self._alert(
                    query,
                    "suspicious_keyword",
                    "high",
                    f"Risky keyword '{needle}' in queried domain",
                    {"keyword": needle, "description": RULES["suspicious_keyword"]},
                )
        return None

    def _tld_alert(self, query: DNSQuery) -> Alert | None:
        labels = domain_labels(query.domain)
        if not labels:
            return None
        tld = labels[-1]
        if tld in {item.lower().lstrip(".") for item in self.config.suspicious_tlds}:
            return self._alert(
                query,
                "suspicious_tld",
                "medium",
                f"High-abuse TLD '.{tld}' used",
                {"tld": tld, "description": RULES["suspicious_tld"]},
            )
        return None

    def _entropy_alert(self, query: DNSQuery) -> Alert | None:
        if looks_like_ip(query.domain):
            return None
        for label in domain_labels(query.domain):
            if len(label) < self.config.min_entropy_label_length:
                continue
            if is_punycode(label) or not label.isalnum():
                continue
            score = shannon_entropy(label)
            if score >= self.config.entropy_threshold:
                return self._alert(
                    query,
                    "high_entropy",
                    "medium",
                    f"Random-looking label '{label}' (entropy {score:.2f})",
                    {
                        "label": label,
                        "entropy": round(score, 3),
                        "description": RULES["high_entropy"],
                    },
                )
        return None

    def _long_label_alert(self, query: DNSQuery) -> Alert | None:
        label = longest_label(query.domain)
        if len(label) > self.config.max_label_length:
            return self._alert(
                query,
                "long_label",
                "medium",
                f"Label of {len(label)} characters exceeds maximum",
                {
                    "label": label[:80],
                    "length": len(label),
                    "description": RULES["long_label"],
                },
            )
        return None

    def _depth_alert(self, query: DNSQuery) -> Alert | None:
        depth = subdomain_depth(query.domain)
        if depth > self.config.max_subdomain_depth:
            return self._alert(
                query,
                "deep_subdomain",
                "low",
                f"Subdomain depth {depth} exceeds configured maximum",
                {"depth": depth, "description": RULES["deep_subdomain"]},
            )
        return None

    def _txt_alert(self, query: DNSQuery) -> Alert | None:
        if query.query_type.upper() not in {"TXT", "NULL"}:
            return None
        length = len(query.answer or "")
        if length > self.config.max_txt_answer_length:
            return self._alert(
                query,
                "txt_tunnel",
                "high",
                f"TXT/NULL answer of {length} bytes may carry tunnelled data",
                {
                    "answer_length": length,
                    "description": RULES["txt_tunnel"],
                },
            )
        return None

    def _prune(self, queue: deque[float], now: float, window: float) -> None:
        while queue and now - queue[0] > window:
            queue.popleft()

    def _rate_alert(self, query: DNSQuery) -> Alert | None:
        now = query.timestamp
        window = self.config.rate_window
        queue = self._query_times[query.source_ip]
        queue.append(now)
        self._prune(queue, now, window)
        count = len(queue)
        if count < self.config.rate_threshold:
            return None
        return self._alert(
            query,
            "rate_limit",
            "high",
            f"{count} queries in {window:.0f}s (limit {self.config.rate_threshold})",
            {
                "count": count,
                "window": window,
                "description": RULES["rate_limit"],
            },
            cooldown=window / 2,
        )

    def _nxdomain_alert(self, query: DNSQuery) -> Alert | None:
        if query.response_code.upper() not in {"NXDOMAIN"}:
            return None
        now = query.timestamp
        window = self.config.nxdomain_window
        queue = self._nxdomain_times[query.source_ip]
        queue.append(now)
        self._prune(queue, now, window)
        count = len(queue)
        if count < self.config.nxdomain_threshold:
            return None
        return self._alert(
            query,
            "nxdomain_burst",
            "medium",
            f"{count} NXDOMAIN replies in {window:.0f}s (limit {self.config.nxdomain_threshold})",
            {
                "count": count,
                "window": window,
                "description": RULES["nxdomain_burst"],
            },
            cooldown=window / 2,
        )

    def evaluate(self, query: DNSQuery) -> list[Alert]:
        """Run all enabled rules against a query and return triggered alerts."""
        if self._ignored(query.domain):
            return []

        checks = [
            ("suspicious_keyword", self._keyword_alert),
            ("suspicious_tld", self._tld_alert),
            ("high_entropy", self._entropy_alert),
            ("long_label", self._long_label_alert),
            ("deep_subdomain", self._depth_alert),
            ("txt_tunnel", self._txt_alert),
            ("rate_limit", self._rate_alert),
            ("nxdomain_burst", self._nxdomain_alert),
        ]
        alerts: list[Alert] = []
        for name, check in checks:
            if not self._rule_on(name):
                continue
            try:
                alert = check(query)
            except Exception:  # pragma: no cover - never let a rule stop capture
                continue
            if alert is not None:
                alerts.append(alert)
        return alerts

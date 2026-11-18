"""Aggregation layer that turns DNS events into reportable statistics."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import Config
from .detector import DetectionEngine
from .models import Alert, DNSQuery
from .utils import severity_rank


@dataclass
class TimelineBucket:
    timestamp: float
    label: str
    queries: int = 0
    alerts: int = 0


@dataclass
class Analyzer:
    """Collects queries/alerts and exposes report-ready statistics."""

    config: Config = field(default_factory=Config)
    max_queries: int = 100_000
    max_alerts: int = 10_000

    def __post_init__(self) -> None:
        self.detector = DetectionEngine(self.config.detectors)
        self.queries: list[DNSQuery] = []
        self.alerts: list[Alert] = []
        self._domains: Counter[str] = Counter()
        self._ips: Counter[str] = Counter()
        self._ip_domains: dict[str, set[str]] = defaultdict(set)
        self._qtypes: Counter[str] = Counter()
        self._rcodes: Counter[str] = Counter()
        self._severities: Counter[str] = Counter()
        self._rules: Counter[str] = Counter()
        self._alert_times: list[float] = []
        self.started_at: float | None = None
        self.finished_at: float | None = None

    # ------------------------------------------------------------------ ingest
    def ingest(self, query: DNSQuery) -> list[Alert]:
        if self.started_at is None:
            self.started_at = query.timestamp
        self.finished_at = query.timestamp

        alerts = self.detector.evaluate(query)
        if len(self.queries) < self.max_queries:
            self.queries.append(query)
        self._domains[query.domain] += 1
        self._ips[query.source_ip] += 1
        self._ip_domains[query.source_ip].add(query.domain)
        self._qtypes[query.query_type.upper()] += 1
        self._rcodes[query.response_code.upper()] += 1

        for alert in alerts:
            if len(self.alerts) < self.max_alerts:
                self.alerts.append(alert)
            self._severities[alert.severity.lower()] += 1
            self._rules[alert.rule] += 1
            self._alert_times.append(alert.timestamp)
        return alerts

    def ingest_many(self, queries: Iterable[DNSQuery]) -> list[Alert]:
        produced: list[Alert] = []
        for query in queries:
            produced.extend(self.ingest(query))
        return produced

    def import_events(
        self, queries: Iterable[DNSQuery], alerts: Iterable[Alert] | None = None
    ) -> None:
        """Load persisted events directly (bypasses re-detection)."""
        for query in queries:
            if self.started_at is None or query.timestamp < self.started_at:
                self.started_at = query.timestamp
            if self.finished_at is None or query.timestamp > self.finished_at:
                self.finished_at = query.timestamp
            if len(self.queries) < self.max_queries:
                self.queries.append(query)
            self._domains[query.domain] += 1
            self._ips[query.source_ip] += 1
            self._ip_domains[query.source_ip].add(query.domain)
            self._qtypes[query.query_type.upper()] += 1
            self._rcodes[query.response_code.upper()] += 1
        for alert in alerts or []:
            if len(self.alerts) < self.max_alerts:
                self.alerts.append(alert)
            self._severities[alert.severity.lower()] += 1
            self._rules[alert.rule] += 1
            self._alert_times.append(alert.timestamp)

    # ----------------------------------------------------------------- queries
    @property
    def total_queries(self) -> int:
        return sum(self._domains.values())

    @property
    def total_alerts(self) -> int:
        return sum(self._severities.values())

    def top_domains(self, limit: int = 10) -> list[tuple[str, int]]:
        return self._domains.most_common(limit)

    def top_ips(self, limit: int = 10) -> list[tuple[str, int, int]]:
        ranked = sorted(self._ips.items(), key=lambda item: item[1], reverse=True)[:limit]
        return [(ip, count, len(self._ip_domains[ip])) for ip, count in ranked]

    def query_types(self) -> list[tuple[str, int]]:
        return self._qtypes.most_common()

    def response_codes(self) -> list[tuple[str, int]]:
        return self._rcodes.most_common()

    def alert_counts(self) -> dict[str, int]:
        return dict(sorted(self._severities.items(), key=lambda item: -severity_rank(item[0])))

    def rule_counts(self) -> list[tuple[str, int]]:
        return self._rules.most_common()

    def alerts_sorted(self, limit: int | None = None) -> list[Alert]:
        ordered = sorted(
            self.alerts,
            key=lambda alert: (-severity_rank(alert.severity), -alert.timestamp),
        )
        return ordered[:limit] if limit else ordered

    def timeline(self, bucket_seconds: int = 60) -> list[TimelineBucket]:
        if not self.queries:
            return []
        start = int(min(q.timestamp for q in self.queries) // bucket_seconds) * bucket_seconds
        end = int(max(q.timestamp for q in self.queries) // bucket_seconds) * bucket_seconds
        query_buckets: Counter[int] = Counter(
            int(q.timestamp // bucket_seconds) * bucket_seconds for q in self.queries
        )
        alert_buckets: Counter[int] = Counter(
            int(t // bucket_seconds) * bucket_seconds for t in self._alert_times
        )
        result: list[TimelineBucket] = []
        for ts in range(start, end + 1, bucket_seconds):
            label = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M")
            result.append(
                TimelineBucket(
                    timestamp=ts,
                    label=label,
                    queries=query_buckets.get(ts, 0),
                    alerts=alert_buckets.get(ts, 0),
                )
            )
        return result

    def duration_seconds(self) -> float:
        if self.started_at is None or self.finished_at is None:
            return 0.0
        return max(0.0, self.finished_at - self.started_at)

    def to_dict(self, top_n: int = 10) -> dict:
        """Return a JSON-serialisable snapshot used by all reporters."""
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "window": {
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "duration_seconds": round(self.duration_seconds(), 2),
            },
            "summary": {
                "total_queries": self.total_queries,
                "unique_domains": len(self._domains),
                "unique_source_ips": len(self._ips),
                "total_alerts": self.total_alerts,
                "queries_per_second": round(
                    self.total_queries / self.duration_seconds(), 2
                )
                if self.duration_seconds()
                else 0,
            },
            "top_domains": [
                {"domain": name, "count": count} for name, count in self.top_domains(top_n)
            ],
            "top_ips": [
                {"ip": ip, "queries": count, "unique_domains": unique}
                for ip, count, unique in self.top_ips(top_n)
            ],
            "query_types": [
                {"type": name, "count": count} for name, count in self.query_types()
            ],
            "response_codes": [
                {"code": name, "count": count} for name, count in self.response_codes()
            ],
            "alerts_by_severity": self.alert_counts(),
            "alerts_by_rule": [
                {"rule": name, "count": count} for name, count in self.rule_counts()
            ],
            "timeline": [
                {
                    "timestamp": point.timestamp,
                    "label": point.label,
                    "queries": point.queries,
                    "alerts": point.alerts,
                }
                for point in self.timeline()
            ],
            "alerts": [alert.to_dict() for alert in self.alerts_sorted(top_n)],
            "config": {
                "rate_threshold": self.config.detectors.rate_threshold,
                "rate_window": self.config.detectors.rate_window,
                "entropy_threshold": self.config.detectors.entropy_threshold,
                "enabled_rules": self.detector.enabled_rules,
            },
        }

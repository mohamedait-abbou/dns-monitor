"""Pluggable sinks for queries and alerts (JSON Lines, SQLite, CSV)."""

from __future__ import annotations

import csv
import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from .models import Alert, DNSQuery
from .utils import ensure_parent

QUERY_COLUMNS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "domain",
    "query_type",
    "response_code",
    "answer",
    "ttl",
    "protocol",
    "bytes_sent",
]


class EventSink(Protocol):
    def write_query(self, query: DNSQuery) -> None: ...

    def write_alert(self, alert: Alert) -> None: ...

    def close(self) -> None: ...


class JSONLSink:
    """One JSON object per line, prefixed with ``kind`` for easy filtering."""

    def __init__(self, path: str | Path) -> None:
        self.path = ensure_parent(path)
        self.file = self.path.open("w", encoding="utf-8")

    def write_query(self, query: DNSQuery) -> None:
        self.file.write(json.dumps({"kind": "query", **query.to_dict()}) + "\n")

    def write_alert(self, alert: Alert) -> None:
        self.file.write(json.dumps({"kind": "alert", **alert.to_dict()}) + "\n")

    def close(self) -> None:
        self.file.close()


class CSVSink:
    """Flat CSV of DNS queries (alerts are not written to CSV)."""

    def __init__(self, path: str | Path) -> None:
        self.path = ensure_parent(path)
        self.file = self.path.open("w", encoding="utf-8", newline="")
        self.writer = csv.DictWriter(self.file, fieldnames=QUERY_COLUMNS)
        self.writer.writeheader()

    def write_query(self, query: DNSQuery) -> None:
        self.writer.writerow(query.to_dict())

    def write_alert(self, alert: Alert) -> None:
        return None

    def close(self) -> None:
        self.file.close()


class SQLiteSink:
    """Normalised SQLite storage, queryable after the capture session."""

    def __init__(self, path: str | Path) -> None:
        self.path = ensure_parent(path)
        self.connection = sqlite3.connect(self.path)
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT,
                domain TEXT NOT NULL,
                query_type TEXT,
                response_code TEXT,
                answer TEXT,
                ttl INTEGER,
                protocol TEXT,
                bytes_sent INTEGER
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                domain TEXT,
                message TEXT,
                metadata TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain);
            CREATE INDEX IF NOT EXISTS idx_queries_source ON queries(source_ip);
            CREATE INDEX IF NOT EXISTS idx_queries_time ON queries(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);
            """
        )
        self.connection.commit()

    def write_query(self, query: DNSQuery) -> None:
        data = query.to_dict()
        self.connection.execute(
            "INSERT INTO queries (" + ", ".join(QUERY_COLUMNS) + ") VALUES ("
            + ", ".join("?" for _ in QUERY_COLUMNS) + ")",
            tuple(data[column] for column in QUERY_COLUMNS),
        )
        self.connection.commit()

    def write_alert(self, alert: Alert) -> None:
        self.connection.execute(
            "INSERT INTO alerts (timestamp, rule, severity, source_ip, domain, message, metadata)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                alert.timestamp,
                alert.rule,
                alert.severity,
                alert.source_ip,
                alert.domain,
                alert.message,
                json.dumps(alert.metadata),
            ),
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.commit()
        self.connection.close()


class MultiSink:
    def __init__(self, sinks: Iterable[EventSink] = ()) -> None:
        self.sinks: list[EventSink] = list(sinks)

    def add(self, sink: EventSink) -> None:
        self.sinks.append(sink)

    def write_query(self, query: DNSQuery) -> None:
        for sink in self.sinks:
            sink.write_query(query)

    def write_alert(self, alert: Alert) -> None:
        for sink in self.sinks:
            sink.write_alert(alert)

    def close(self) -> None:
        for sink in self.sinks:
            sink.close()


def load_sqlite(path: str | Path) -> tuple[list[DNSQuery], list[Alert]]:
    """Read all events back from a SQLite database produced by SQLiteSink."""
    connection = sqlite3.connect(Path(path).expanduser())
    connection.row_factory = sqlite3.Row
    try:
        queries = [
            DNSQuery.from_dict(dict(row))
            for row in connection.execute("SELECT * FROM queries ORDER BY timestamp")
        ]
        alerts = []
        for row in connection.execute("SELECT * FROM alerts ORDER BY timestamp"):
            payload = dict(row)
            payload["metadata"] = json.loads(payload.get("metadata") or "{}")
            alerts.append(Alert.from_dict(payload))
        return queries, alerts
    finally:
        connection.close()


def load_jsonl(path: str | Path) -> tuple[list[DNSQuery], list[Alert]]:
    queries: list[DNSQuery] = []
    alerts: list[Alert] = []
    with Path(path).expanduser().open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            kind = payload.pop("kind", "query")
            if kind == "alert":
                alerts.append(Alert.from_dict(payload))
            else:
                queries.append(DNSQuery.from_dict(payload))
    return queries, alerts

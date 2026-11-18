import csv
import json

from dns_monitor.models import Alert
from dns_monitor.storage import (
    CSVSink,
    JSONLSink,
    MultiSink,
    SQLiteSink,
    load_jsonl,
    load_sqlite,
)


def _alert() -> Alert:
    return Alert(
        timestamp=1_700_000_000.0,
        rule="suspicious_keyword",
        severity="high",
        source_ip="10.0.0.5",
        domain="malware.example.com",
        message="Risky keyword",
        metadata={"keyword": "malware"},
    )


def test_jsonl_roundtrip(tmp_path, query):
    path = tmp_path / "events.jsonl"
    sink = JSONLSink(path)
    sink.write_query(query)
    sink.write_alert(_alert())
    sink.close()

    payloads = [json.loads(line) for line in path.read_text().splitlines()]
    assert payloads[0]["kind"] == "query"
    assert payloads[1]["kind"] == "alert"

    queries, alerts = load_jsonl(path)
    assert len(queries) == 1
    assert queries[0].domain == query.domain
    assert alerts[0].metadata["keyword"] == "malware"


def test_sqlite_roundtrip(tmp_path, query):
    path = tmp_path / "dns.db"
    sink = SQLiteSink(path)
    sink.write_query(query)
    sink.write_alert(_alert())
    sink.close()

    queries, alerts = load_sqlite(path)
    assert len(queries) == 1
    assert queries[0].source_ip == query.source_ip
    assert len(alerts) == 1
    assert alerts[0].rule == "suspicious_keyword"


def test_csv_and_multisink(tmp_path, query):
    csv_path = tmp_path / "queries.csv"
    jsonl_path = tmp_path / "events.jsonl"
    sinks = MultiSink([CSVSink(csv_path), JSONLSink(jsonl_path)])
    sinks.write_query(query)
    sinks.write_alert(_alert())
    sinks.close()

    with csv_path.open() as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["domain"] == query.domain
    assert len(jsonl_path.read_text().splitlines()) == 2

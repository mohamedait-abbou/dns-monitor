from dns_monitor.analyzer import Analyzer
from dns_monitor.models import Alert


def test_ingest_builds_statistics(make_query):
    analyzer = Analyzer()
    queries = [
        make_query(domain="google.com", timestamp=1_700_000_000),
        make_query(domain="google.com", timestamp=1_700_000_010, source_ip="10.0.0.2"),
        make_query(domain="github.com", timestamp=1_700_000_070),
    ]
    alerts = analyzer.ingest_many(queries)
    assert alerts == []
    assert analyzer.total_queries == 3
    assert analyzer.top_domains(2)[0] == ("google.com", 2)
    assert len(analyzer.top_ips(5)) == 2
    assert analyzer.total_alerts == 0
    assert len(analyzer.timeline(bucket_seconds=60)) == 2
    assert analyzer.duration_seconds() == 70


def test_ingest_records_alerts(make_query):
    analyzer = Analyzer()
    alerts = analyzer.ingest(make_query(domain="malware-c2.evil.xyz"))
    assert alerts
    assert analyzer.total_alerts == len(alerts)
    assert analyzer.alert_counts().get("high", 0) >= 1
    assert analyzer.rule_counts()[0][0] in {"suspicious_keyword", "suspicious_tld"}


def test_to_dict_shape(make_query):
    analyzer = Analyzer()
    analyzer.ingest(make_query())
    data = analyzer.to_dict()
    for key in (
        "generated_at",
        "summary",
        "top_domains",
        "top_ips",
        "query_types",
        "response_codes",
        "alerts_by_severity",
        "alerts_by_rule",
        "timeline",
        "alerts",
        "config",
    ):
        assert key in data
    assert data["summary"]["total_queries"] == 1


def test_import_events_bypasses_detection(make_query):
    analyzer = Analyzer()
    alert = Alert(
        timestamp=1_700_000_000,
        rule="manual",
        severity="low",
        source_ip="10.0.0.1",
        domain="example.com",
        message="imported",
    )
    analyzer.import_events([make_query()], [alert])
    assert analyzer.total_queries == 1
    assert analyzer.total_alerts == 1
    assert analyzer.alerts[0].rule == "manual"

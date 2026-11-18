from dns_monitor.config import DetectorConfig
from dns_monitor.detector import DetectionEngine


def rules_for(engine, query) -> list[str]:
    return [alert.rule for alert in engine.evaluate(query)]


def test_keyword_rule(make_query):
    engine = DetectionEngine()
    alerts = engine.evaluate(make_query(domain="malware-c2.example.com"))
    assert "suspicious_keyword" in rules_for(engine, make_query(domain="phishing-login.example.com"))
    assert any(alert.severity == "high" for alert in alerts)
    assert alerts[0].metadata["keyword"] == "malware"


def test_tld_rule(make_query):
    engine = DetectionEngine()
    assert "suspicious_tld" in rules_for(engine, make_query(domain="free-games.xyz"))


def test_entropy_rule(make_query):
    engine = DetectionEngine()
    domain = "a8f3c91d0b7e6a4f2c9d8b7a6e5f4c3.darknet.example"
    alerts = engine.evaluate(make_query(domain=domain))
    assert "high_entropy" in rules_for(engine, make_query(domain=domain))
    assert alerts[0].metadata["entropy"] >= engine.config.entropy_threshold


def test_long_label_and_depth_rules(make_query):
    engine = DetectionEngine()
    assert "long_label" in rules_for(engine, make_query(domain="a" * 45 + ".example.com"))
    assert "deep_subdomain" in rules_for(engine, make_query(domain="a.b.c.d.e.f.example.com"))


def test_txt_tunnel_rule(make_query):
    engine = DetectionEngine()
    query = make_query(query_type="TXT", answer="A" * 200)
    assert "txt_tunnel" in rules_for(engine, query)


def test_rate_limit_rule(make_query):
    engine = DetectionEngine()
    triggered = False
    for index in range(60):
        query = make_query(timestamp=1_700_000_000 + index * 0.01)
        if "rate_limit" in rules_for(engine, query):
            triggered = True
    assert triggered


def test_nxdomain_burst_rule(make_query):
    engine = DetectionEngine()
    triggered = False
    for index in range(12):
        query = make_query(
            timestamp=1_700_000_000 + index * 0.5,
            domain=f"missing{index}.invalid.example",
            response_code="NXDOMAIN",
        )
        if "nxdomain_burst" in rules_for(engine, query):
            triggered = True
    assert triggered


def test_ignored_domains_and_disabled_rules(make_query):
    engine = DetectionEngine()
    assert engine.evaluate(make_query(domain="8.8.8.8.in-addr.arpa")) == []

    engine = DetectionEngine(DetectorConfig(enabled_rules=[]))
    assert engine.evaluate(make_query(domain="malware-c2.evil.xyz")) == []


def test_reset_clears_state(make_query):
    engine = DetectionEngine()
    for index in range(55):
        engine.evaluate(make_query(timestamp=1_700_000_000 + index * 0.01))
    engine.reset()
    assert not engine._query_times
    assert engine.evaluate(make_query(timestamp=1_700_000_100)) == []

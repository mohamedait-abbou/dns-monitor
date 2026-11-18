from dns_monitor.config import DetectorConfig
from dns_monitor.utils import (
    domain_labels,
    longest_label,
    severity_rank,
    shannon_entropy,
    subdomain_depth,
)


def test_entropy_distinguishes_random_and_human_labels():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("www") < 2.0
    assert shannon_entropy("a8f3c91d0b7e6a4f2c9d") > shannon_entropy("example")


def test_domain_helpers():
    assert domain_labels("WWW.Example.COM.") == ["www", "example", "com"]
    assert subdomain_depth("a.b.c.example.com") == 3
    assert subdomain_depth("example.com") == 0
    assert longest_label("short.verylonglabel.example.com") == "verylonglabel"


def test_severity_rank_ordering():
    assert severity_rank("critical") > severity_rank("high") > severity_rank("low")
    assert severity_rank("unknown") == 0


def test_default_detector_config_is_sane():
    config = DetectorConfig()
    assert config.rate_threshold > 0
    assert config.rate_window > 0
    assert "rate_limit" in config.enabled_rules
    assert len(config.suspicious_keywords) > 0

import pytest

from dns_monitor.capture import generate_synthetic_queries, parse_packet


def test_parse_packet_extracts_dns_fields():
    pytest.importorskip("scapy")
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, UDP

    packet = (
        IP(src="192.168.1.10", dst="1.1.1.1")
        / UDP(sport=53124, dport=53)
        / DNS(
            id=42,
            qr=1,
            qd=DNSQR(qname="example.com", qtype=1),
            an=DNSRR(rrname="example.com", rdata="93.184.216.34", ttl=300),
        )
    )
    packet.time = 1_700_000_000.5
    query = parse_packet(packet)
    assert query is not None
    assert query.domain == "example.com"
    assert query.source_ip == "192.168.1.10"
    assert query.query_type == "A"
    assert query.response_code == "NOERROR"
    assert query.answer == "93.184.216.34"
    assert query.ttl == 300
    assert query.timestamp == 1_700_000_000.5


def test_parse_packet_ignores_non_dns():
    pytest.importorskip("scapy")
    from scapy.layers.inet import IP, TCP

    assert parse_packet(IP() / TCP(dport=80)) is None


def test_parse_packet_skips_malformed_dns():
    pytest.importorskip("scapy")
    from scapy.layers.dns import DNS
    from scapy.layers.inet import IP, UDP

    assert parse_packet(IP() / UDP() / DNS(qd=[])) is None


def test_simulation_is_deterministic_and_varied():
    first = list(generate_synthetic_queries(120, seed=11, start_time=1_700_000_000))
    second = list(generate_synthetic_queries(120, seed=11, start_time=1_700_000_000))
    assert first == second
    assert len(first) == 120
    assert len({query.source_ip for query in first}) >= 3
    assert any(query.response_code == "NXDOMAIN" for query in first)
    assert any(len(query.answer) > 120 for query in first)

"""Live/offline packet capture plus a deterministic traffic simulator."""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Iterator
from pathlib import Path

from .config import CaptureConfig
from .models import DNSQuery

QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    65: "HTTPS",
    255: "ANY",
}
RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

BENIGN_DOMAINS = [
    "google.com",
    "www.google.com",
    "github.com",
    "api.github.com",
    "cloudflare.com",
    "wikipedia.org",
    "python.org",
    "pypi.org",
    "stackoverflow.com",
    "example.com",
    "mail.example.net",
    "cdn.example.org",
]
THREAT_DOMAINS = [
    "malware-c2.evil.xyz",
    "phishing-login.secure-verify.top",
    "botnet-node-01.su",
    "q9f3a8b2c1d7e6f5a0b9c8d7e4f3a2b1.darknet.tk",
    "a.b.c.d.e.f.g.exfiltration.example.com",
    "this-is-an-extremely-long-label-that-should-trigger-the-tunnelling-rule.example.net",
]

QueryHandler = Callable[[DNSQuery], None]


def _as_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value) if value is not None else ""


def parse_packet(packet) -> DNSQuery | None:
    """Convert a Scapy packet into a :class:`DNSQuery` (None if not DNS)."""
    try:
        from scapy.layers.dns import DNS
        from scapy.layers.inet import IP, TCP
    except ImportError as exc:  # pragma: no cover - guarded at CLI level
        raise RuntimeError("Scapy is required for packet capture") from exc

    try:
        if not packet.haslayer(DNS):
            return None
        dns = packet[DNS]
        qd = dns.qd
        if qd is None or (isinstance(qd, list) and not qd):
            return None
        question = qd[0] if isinstance(qd, list) else qd
        domain = _as_text(getattr(question, "qname", "")).rstrip(".").lower()
        if not domain:
            return None

        qtype_num = int(getattr(question, "qtype", 1) or 1)
        rcode_num = int(getattr(dns, "rcode", 0) or 0)
        answer = ""
        ttl: int | None = None
        an = dns.an
        if an is not None:
            record = an[0] if isinstance(an, list) and an else (an if not isinstance(an, list) else None)
            if record is not None:
                answer = _as_text(getattr(record, "rdata", ""))[:500]
                raw_ttl = getattr(record, "ttl", None)
                ttl = int(raw_ttl) if raw_ttl is not None else None

        source_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
        destination_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"

        return DNSQuery(
            timestamp=float(getattr(packet, "time", time.time())),
            source_ip=source_ip,
            destination_ip=destination_ip,
            domain=domain,
            query_type=QTYPE_NAMES.get(qtype_num, f"TYPE{qtype_num}"),
            response_code=RCODE_NAMES.get(rcode_num, f"RCODE{rcode_num}"),
            answer=answer,
            ttl=ttl,
            protocol="TCP" if packet.haslayer(TCP) else "UDP",
            bytes_sent=len(packet),
        )
    except (AttributeError, IndexError, TypeError, ValueError):
        # Malformed or truncated DNS payloads are skipped, never fatal.
        return None


def _packet_dispatcher(handler: QueryHandler) -> QueryHandler:
    def dispatch(packet) -> None:
        query = parse_packet(packet)
        if query is not None:
            handler(query)

    return dispatch


def capture_live(config: CaptureConfig, handler: QueryHandler) -> int:
    """Capture live DNS packets using Scapy. Returns the number of packets seen."""
    from scapy.all import sniff

    kwargs: dict = {
        "filter": config.bpf_filter,
        "prn": _packet_dispatcher(handler),
        "store": 0,
        "promisc": config.promiscuous,
    }
    if config.interface:
        kwargs["iface"] = config.interface
    if config.duration is not None:
        kwargs["timeout"] = config.duration
    sniff(**kwargs)
    return 0


def capture_pcap(path: str | Path, handler: QueryHandler, bpf_filter: str | None = None) -> int:
    """Replay a pcap/pcapng file through the same parsing pipeline."""
    from scapy.all import sniff

    pcap_path = Path(path).expanduser()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
    kwargs: dict = {
        "offline": str(pcap_path),
        "prn": _packet_dispatcher(handler),
        "store": 0,
    }
    if bpf_filter:
        kwargs["filter"] = bpf_filter
    sniff(**kwargs)
    return 0


def generate_synthetic_queries(
    count: int = 500,
    seed: int = 7,
    start_time: float | None = None,
    span_seconds: float = 600.0,
) -> Iterator[DNSQuery]:
    """Yield deterministic mixed traffic, including known threat scenarios.

    This powers ``dns-monitor run --simulate`` and the demo report so the
    project can be demonstrated without root privileges or a live network.
    """
    rng = random.Random(seed)
    base = start_time if start_time is not None else time.time() - 600
    benign_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.23", "10.0.0.8"]
    attacker = "192.168.1.42"

    # Two short, high-volume episodes make the stateful rules observable in
    # the demo report without needing a real attacker on the network.
    flood_start = int(count * 0.12)
    flood_len = min(90, max(20, count // 5))
    nx_start = flood_start + flood_len
    nx_len = min(40, max(10, count // 12))

    for index in range(count):
        progress = index / max(1, count - 1)
        timestamp = base + progress * span_seconds
        scenario = rng.random()

        if flood_start <= index < nx_start:  # rate-limit flood
            offset = index - flood_start
            timestamp = base + span_seconds * 0.20 + offset * 0.05
            query = DNSQuery(
                timestamp=timestamp,
                source_ip=attacker,
                destination_ip="1.1.1.1",
                domain=rng.choice(BENIGN_DOMAINS[:4]),
                query_type="A",
                response_code="NOERROR",
                answer="93.184.216.34",
                ttl=300,
                bytes_sent=75,
            )
        elif nx_start <= index < nx_start + nx_len:  # NXDOMAIN burst
            offset = index - nx_start
            timestamp = base + span_seconds * 0.38 + offset * 0.1
            label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(14))
            query = DNSQuery(
                timestamp=timestamp,
                source_ip=attacker,
                destination_ip="8.8.8.8",
                domain=f"{label}.missing.invalid",
                query_type="A",
                response_code="NXDOMAIN",
                bytes_sent=68,
            )
        elif scenario < 0.20:  # TXT tunnelling
            payload = "".join(rng.choice("abcdef0123456789") for _ in range(180))
            query = DNSQuery(
                timestamp=timestamp,
                source_ip=attacker,
                destination_ip="8.8.8.8",
                domain=rng.choice(THREAT_DOMAINS[3:]),
                query_type="TXT",
                response_code="NOERROR",
                answer=payload,
                ttl=60,
                bytes_sent=240,
            )
        elif scenario < 0.30:  # named threats
            query = DNSQuery(
                timestamp=timestamp,
                source_ip=rng.choice(benign_ips + [attacker]),
                destination_ip="1.1.1.1",
                domain=rng.choice(THREAT_DOMAINS[:3]),
                query_type=rng.choice(["A", "A", "AAAA", "TXT"]),
                response_code=rng.choice(["NOERROR", "NOERROR", "NXDOMAIN"]),
                answer="185.220.101.7",
                ttl=120,
                bytes_sent=90,
            )
        else:  # normal background traffic
            query = DNSQuery(
                timestamp=timestamp,
                source_ip=rng.choice(benign_ips),
                destination_ip=rng.choice(["1.1.1.1", "8.8.8.8", "9.9.9.9"]),
                domain=rng.choice(BENIGN_DOMAINS),
                query_type=rng.choices(["A", "AAAA", "MX", "CNAME"], [70, 20, 5, 5])[0],
                response_code="NOERROR",
                answer="142.250.185.78",
                ttl=300,
                bytes_sent=rng.randint(60, 110),
            )
        yield query


def run_simulation(count: int, seed: int, handler: QueryHandler) -> None:
    for query in generate_synthetic_queries(count=count, seed=seed):
        handler(query)

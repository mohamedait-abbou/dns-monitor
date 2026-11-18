#!/usr/bin/env python3
"""Create a synthetic PCAP so ``dns-monitor analyze`` can be demonstrated.

Usage:
    python examples/generate_pcap.py --output sample.pcap --count 300
    dns-monitor analyze sample.pcap --html out/pcap-report.html
"""

from __future__ import annotations

import argparse
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_monitor.capture import QTYPE_NAMES, RCODE_NAMES, generate_synthetic_queries  # noqa: E402
from dns_monitor.models import DNSQuery  # noqa: E402


def query_to_packet(query: DNSQuery):
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, UDP

    qtype = next((key for key, name in QTYPE_NAMES.items() if name == query.query_type), 1)
    rcode = next((key for key, name in RCODE_NAMES.items() if name == query.response_code), 0)
    question = DNSQR(qname=query.domain, qtype=qtype)

    answer = None
    if query.answer and query.query_type == "TXT":
        answer = DNSRR(
            rrname=query.domain,
            type=16,
            rdata=query.answer[:200].encode("utf-8"),
            ttl=query.ttl or 60,
        )
    elif query.answer and query.query_type in {"A", "AAAA"}:
        answer = DNSRR(rrname=query.domain, rdata=query.answer, ttl=query.ttl or 60)

    packet = (
        IP(src=query.destination_ip, dst=query.source_ip)
        / UDP(sport=53, dport=40000 + (zlib.crc32(query.source_ip.encode()) % 20000))
        / DNS(
            id=zlib.crc32(query.domain.encode()) % 65535,
            qr=1,
            ra=1,
            rcode=rcode,
            qd=question,
            an=answer,
        )
    )
    packet.time = query.timestamp
    return packet


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="sample.pcap", help="destination pcap path")
    parser.add_argument("--count", type=int, default=300, help="number of DNS packets")
    parser.add_argument("--seed", type=int, default=7, help="random seed")
    args = parser.parse_args()

    from scapy.all import wrpcap

    packets = [
        query_to_packet(query)
        for query in generate_synthetic_queries(count=args.count, seed=args.seed)
    ]
    target = Path(args.output).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(target), packets)
    print(f"[+] wrote {len(packets)} DNS packets to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

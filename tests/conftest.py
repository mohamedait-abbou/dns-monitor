"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_monitor.config import Config  # noqa: E402
from dns_monitor.models import DNSQuery  # noqa: E402


@pytest.fixture
def config() -> Config:
    return Config()


@pytest.fixture
def query() -> DNSQuery:
    return DNSQuery(
        timestamp=1_700_000_000.0,
        source_ip="192.168.1.10",
        destination_ip="1.1.1.1",
        domain="www.example.com",
        query_type="A",
        response_code="NOERROR",
        answer="93.184.216.34",
        ttl=300,
        protocol="UDP",
        bytes_sent=80,
    )


@pytest.fixture
def make_query():
    def factory(**overrides) -> DNSQuery:
        payload = {
            "timestamp": 1_700_000_000.0,
            "source_ip": "192.168.1.10",
            "destination_ip": "1.1.1.1",
            "domain": "www.example.com",
            "query_type": "A",
            "response_code": "NOERROR",
        }
        payload.update(overrides)
        return DNSQuery(**payload)

    return factory

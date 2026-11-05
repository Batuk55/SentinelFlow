"""Synthetic network event generator with ground truth labels.

All IPs come from private ranges (10.0.0.0/8) or the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so nothing here refers to real hosts.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.schemas.event import EventIn
from app.utils.time import utcnow

# (source_ip, rule) pairs that SHOULD be detected in the default scenario.
EXPECTED_DETECTIONS: set[tuple[str, str]] = {
    ("203.0.113.10", "failed_login_bruteforce"),
    ("198.51.100.23", "port_scan_pattern"),
    ("192.0.2.77", "high_connection_frequency"),
    ("203.0.113.99", "suspicious_port_activity"),
    ("198.51.100.200", "repeated_connections"),
    ("192.0.2.150", "unusual_destination_port"),
}
BENIGN_SOURCES = [f"10.0.0.{i}" for i in range(10, 20)]
BENIGN_TARGETS = [("10.0.1.5", 443), ("10.0.1.6", 80), ("10.0.1.7", 53), ("10.0.1.8", 22), ("10.0.1.9", 5432)]


@dataclass
class Scenario:
    events: list[EventIn]
    expected: set[tuple[str, str]]


def _event(ts, src, dst, dport, etype="connection", status="success", attempts=1, proto="TCP", rng=None):
    sport = (rng or random).randint(40000, 65000)
    return EventIn(
        source_ip=src, destination_ip=dst, source_port=sport, destination_port=dport,
        protocol=proto, timestamp=ts, event_type=etype, connection_status=status,
        connection_attempts=attempts,
    )


def generate_benign(rng: random.Random, start: datetime, count: int = 150) -> list[EventIn]:
    events = []
    for _ in range(count):
        src = rng.choice(BENIGN_SOURCES)
        dst, port = rng.choice(BENIGN_TARGETS)
        ts = start + timedelta(seconds=rng.uniform(0, 600))
        if rng.random() < 0.03:  # occasional single mistyped password: normal behaviour
            events.append(_event(ts, src, dst, 22, "login_attempt", "failed", rng=rng))
        else:
            events.append(_event(ts, src, dst, port, rng=rng))
    return events


def generate_attacks(rng: random.Random, start: datetime) -> list[EventIn]:
    ev: list[EventIn] = []
    # Brute force: 12 failed SSH logins in ~44s
    for i in range(12):
        ev.append(_event(start + timedelta(seconds=60 + i * 4), "203.0.113.10", "10.0.1.8", 22,
                         "login_attempt", "failed", rng=rng))
    # Port scan: 30 distinct ports in ~29s
    for i in range(30):
        ev.append(_event(start + timedelta(seconds=120 + i), "198.51.100.23", "10.0.1.10", 1000 + i * 7,
                         status="reset" if i % 2 else "failed", rng=rng))
    # Connection flood: 6 events x 40 attempts = 240 attempts in 30s
    for i in range(6):
        ev.append(_event(start + timedelta(seconds=200 + i * 5), "192.0.2.77", "10.0.1.20", 443,
                         attempts=40, rng=rng))
    # Suspicious port: 4 events to port 4444 over 90s
    for i in range(4):
        ev.append(_event(start + timedelta(seconds=300 + i * 30), "203.0.113.99", "10.0.2.5", 4444, rng=rng))
    # Repeated connections: 20 connections to the same service in ~4 min
    for i in range(20):
        ev.append(_event(start + timedelta(seconds=100 + i * 12), "198.51.100.200", "10.0.1.30", 443, rng=rng))
    # Unusual ports: 6 events to 6 different unexpected ports (fewer than the port-scan threshold)
    for i in range(6):
        ev.append(_event(start + timedelta(seconds=400 + i * 15), "192.0.2.150", "10.0.1.40", 7000 + i,
                         status="failed", rng=rng))
    return ev


def generate_scenario(seed: int = 42, base_time: datetime | None = None) -> Scenario:
    rng = random.Random(seed)
    start = (base_time or utcnow()) - timedelta(minutes=15)
    events = generate_benign(rng, start) + generate_attacks(rng, start)
    events.sort(key=lambda e: e.timestamp)
    return Scenario(events=events, expected=set(EXPECTED_DETECTIONS))

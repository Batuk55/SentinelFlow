"""Configurable rule-based threat detection engine.

Pure Python: it knows nothing about FastAPI, SQLAlchemy or the frontend. It receives a list of
`EventRecord` objects and returns a list of `Detection` objects. Thresholds, windows, severities
and port lists all come from a JSON config (app/detection_rules.json by default).

Every rule uses a sliding time window per source IP and reports the *peak* window it found.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Hashable, Iterable

from app.utils.time import utcnow

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "detection_rules.json"


@dataclass(frozen=True)
class EventRecord:
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    event_type: str
    connection_status: str
    connection_attempts: int
    timestamp: datetime
    id: int | None = None


@dataclass
class Detection:
    rule: str
    category: str
    severity: str
    source_ip: str
    description: str
    detected_at: datetime
    evidence: dict
    event_ids: list[int] = field(default_factory=list)  # all events in the peak window


def load_rules(path: str | Path | None = None) -> dict:
    with open(path or DEFAULT_RULES_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _severity_for(value: int, cfg: dict) -> str:
    severity = cfg["severity"]
    for tier in cfg.get("escalation", []):
        if value >= tier["at"] and SEVERITY_ORDER.index(tier["severity"]) > SEVERITY_ORDER.index(severity):
            severity = tier["severity"]
    return severity


def _peak_window(
    events: list[EventRecord],
    window_seconds: int,
    weight: Callable[[EventRecord], int] = lambda e: 1,
    distinct_key: Callable[[EventRecord], Hashable] | None = None,
) -> tuple[int, list[EventRecord]]:
    """Slide a time window over time-sorted events and return (best_value, events_in_best_window).

    value = sum of weights, or the number of distinct keys when `distinct_key` is given.
    """
    if not events:
        return 0, []
    left, total, counter = 0, 0, Counter()
    best_value, best_range = 0, (0, -1)
    for right, event in enumerate(events):
        if distinct_key:
            counter[distinct_key(event)] += 1
        else:
            total += weight(event)
        while (event.timestamp - events[left].timestamp).total_seconds() > window_seconds:
            old = events[left]
            if distinct_key:
                key = distinct_key(old)
                counter[key] -= 1
                if counter[key] == 0:
                    del counter[key]
            else:
                total -= weight(old)
            left += 1
        value = len(counter) if distinct_key else total
        if value > best_value:
            best_value, best_range = value, (left, right)
    return best_value, events[best_range[0] : best_range[1] + 1]


def _make_detection(
    rule: str, cfg: dict, ip: str, value: int, window: list[EventRecord], description: str,
    now: datetime, extra: dict | None = None,
) -> Detection:
    evidence = {
        "rule": rule,
        "observed_value": value,
        "threshold": cfg["threshold"],
        "window_seconds": cfg["window_seconds"],
        "window_start": window[0].timestamp.isoformat(),
        "window_end": window[-1].timestamp.isoformat(),
        "events_in_window": len(window),
        "sample_event_ids": [e.id for e in window if e.id is not None][:10],
        "destination_ips": sorted({e.destination_ip for e in window})[:10],
        "destination_ports": sorted({e.destination_port for e in window})[:20],
    }
    evidence.update(extra or {})
    return Detection(
        rule=rule,
        category=cfg["category"],
        severity=_severity_for(value, cfg),
        source_ip=ip,
        description=description,
        detected_at=now,
        evidence=evidence,
        event_ids=[e.id for e in window if e.id is not None],
    )


# ---------------------------------------------------------------- rules
# Each rule: (rule_name, source_ip, time-sorted events of that source, rule config, now) -> Detection | None

def _rule_failed_login(name, ip, events, cfg, now):
    failed = [e for e in events if e.event_type == "login_attempt" and e.connection_status == "failed"]
    value, window = _peak_window(failed, cfg["window_seconds"], weight=lambda e: e.connection_attempts)
    if value < cfg["threshold"]:
        return None
    desc = (
        f"{value} failed login attempts from {ip} within {cfg['window_seconds']} seconds "
        f"(threshold {cfg['threshold']})."
    )
    return _make_detection(name, cfg, ip, value, window, desc, now, {"failed_attempts": value})


def _rule_high_frequency(name, ip, events, cfg, now):
    value, window = _peak_window(events, cfg["window_seconds"], weight=lambda e: e.connection_attempts)
    if value < cfg["threshold"]:
        return None
    desc = (
        f"{ip} made {value} connection attempts within {cfg['window_seconds']} seconds "
        f"(threshold {cfg['threshold']})."
    )
    return _make_detection(name, cfg, ip, value, window, desc, now, {"total_attempts": value})


def _rule_port_scan(name, ip, events, cfg, now):
    by_target: dict[str, list[EventRecord]] = defaultdict(list)
    for e in events:
        by_target[e.destination_ip].append(e)
    best_value, best_window, best_target = 0, [], None
    for target, group in by_target.items():
        value, window = _peak_window(
            group, cfg["window_seconds"], distinct_key=lambda e: e.destination_port
        )
        if value > best_value:
            best_value, best_window, best_target = value, window, target
    if best_value < cfg["threshold"]:
        return None
    desc = (
        f"{ip} contacted {best_value} distinct ports on {best_target} within "
        f"{cfg['window_seconds']} seconds (threshold {cfg['threshold']}), consistent with port scanning."
    )
    return _make_detection(
        name, cfg, ip, best_value, best_window, desc, now,
        {"target_ip": best_target, "distinct_ports": best_value},
    )


def _rule_suspicious_ports(name, ip, events, cfg, now):
    risky = set(cfg["suspicious_ports"])
    selected = [e for e in events if e.destination_port in risky]
    value, window = _peak_window(selected, cfg["window_seconds"])
    if value < cfg["threshold"]:
        return None
    ports = sorted({e.destination_port for e in window})
    desc = (
        f"{ip} sent {value} events to commonly abused ports {ports} within "
        f"{cfg['window_seconds']} seconds (threshold {cfg['threshold']})."
    )
    return _make_detection(name, cfg, ip, value, window, desc, now, {"suspicious_ports_hit": ports})


def _rule_repeated_connections(name, ip, events, cfg, now):
    by_target: dict[tuple[str, int], list[EventRecord]] = defaultdict(list)
    for e in events:
        if e.event_type == "connection":
            by_target[(e.destination_ip, e.destination_port)].append(e)
    best_value, best_window, best_target = 0, [], None
    for target, group in by_target.items():
        value, window = _peak_window(group, cfg["window_seconds"])
        if value > best_value:
            best_value, best_window, best_target = value, window, target
    if best_value < cfg["threshold"]:
        return None
    desc = (
        f"{ip} opened {best_value} connections to {best_target[0]}:{best_target[1]} within "
        f"{cfg['window_seconds']} seconds (threshold {cfg['threshold']})."
    )
    return _make_detection(
        name, cfg, ip, best_value, best_window, desc, now,
        {"target_ip": best_target[0], "target_port": best_target[1]},
    )


def _rule_unusual_ports(name, ip, events, cfg, now):
    expected = set(cfg["expected_ports"])
    selected = [e for e in events if e.destination_port not in expected]
    value, window = _peak_window(selected, cfg["window_seconds"])
    if value < cfg["threshold"]:
        return None
    ports = sorted({e.destination_port for e in window})
    desc = (
        f"{ip} sent {value} events to ports outside the expected service list {ports} within "
        f"{cfg['window_seconds']} seconds (threshold {cfg['threshold']})."
    )
    return _make_detection(name, cfg, ip, value, window, desc, now, {"unusual_ports_hit": ports})


RULE_FUNCTIONS: dict[str, Callable] = {
    "failed_login_bruteforce": _rule_failed_login,
    "high_connection_frequency": _rule_high_frequency,
    "port_scan_pattern": _rule_port_scan,
    "suspicious_port_activity": _rule_suspicious_ports,
    "repeated_connections": _rule_repeated_connections,
    "unusual_destination_port": _rule_unusual_ports,
}


class DetectionEngine:
    def __init__(self, config: dict):
        self.rules: dict[str, dict] = {
            name: cfg
            for name, cfg in config.get("rules", {}).items()
            if cfg.get("enabled", True) and name in RULE_FUNCTIONS
        }

    @property
    def max_window_seconds(self) -> int:
        """Longest window of any enabled rule: how far back the ingestion service must look."""
        return max((cfg["window_seconds"] for cfg in self.rules.values()), default=0)

    def analyze(self, events: Iterable[EventRecord], now: datetime | None = None) -> list[Detection]:
        now = now or utcnow()
        by_source: dict[str, list[EventRecord]] = defaultdict(list)
        for event in events:
            by_source[event.source_ip].append(event)

        detections: list[Detection] = []
        for ip, source_events in by_source.items():
            source_events.sort(key=lambda e: e.timestamp)
            fired: dict[str, Detection] = {}
            for name, cfg in self.rules.items():
                result = RULE_FUNCTIONS[name](name, ip, source_events, cfg, now)
                if result:
                    fired[name] = result
            # Suppression: a more specific rule explains the same behaviour, so skip the generic one.
            for name, detection in fired.items():
                suppressors = self.rules[name].get("suppressed_by", [])
                if not any(s in fired for s in suppressors):
                    detections.append(detection)
        return detections

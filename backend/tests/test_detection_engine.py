"""Unit tests for the detection engine. No database or HTTP involved."""
import random
from datetime import datetime, timedelta, timezone

from app.services.detection_engine import DetectionEngine, EventRecord, load_rules
from app.utils.sample_data import generate_benign, generate_scenario

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make(ts_offset, src="203.0.113.5", dst="10.0.0.5", port=22, etype="login_attempt",
         status="failed", attempts=1, eid=None):
    return EventRecord(
        id=eid, source_ip=src, destination_ip=dst, destination_port=port, protocol="TCP",
        event_type=etype, connection_status=status, connection_attempts=attempts,
        timestamp=T0 + timedelta(seconds=ts_offset),
    )


def engine():
    return DetectionEngine(load_rules())


def rules_fired(events):
    return {(d.source_ip, d.rule) for d in engine().analyze(events)}


def test_bruteforce_triggers_at_threshold():
    events = [make(i * 5, eid=i + 1) for i in range(5)]  # 5 failures in 20s
    detections = engine().analyze(events)
    assert [d.rule for d in detections] == ["failed_login_bruteforce"]
    assert detections[0].severity == "High"
    assert detections[0].evidence["failed_attempts"] == 5


def test_bruteforce_not_triggered_below_threshold():
    assert rules_fired([make(i * 5) for i in range(4)]) == set()


def test_bruteforce_respects_time_window():
    # 5 failures but spread over 10 minutes -> never 5 inside any 60s window
    assert rules_fired([make(i * 150) for i in range(5)]) == set()


def test_bruteforce_escalates_to_critical():
    events = [make(i, eid=i + 1) for i in range(25)]
    assert engine().analyze(events)[0].severity == "Critical"


def test_successful_logins_are_ignored():
    assert rules_fired([make(i, status="success") for i in range(30)]) == set()


def test_port_scan_detected_and_suppresses_generic_rules():
    events = [make(i, port=2000 + i, etype="connection", status="failed") for i in range(20)]
    fired = {rule for _, rule in rules_fired(events)}
    assert fired == {"port_scan_pattern"}  # unusual_destination_port is suppressed


def test_high_connection_frequency_uses_attempt_counts():
    events = [make(i * 5, port=443, etype="connection", status="success", attempts=30) for i in range(4)]
    fired = {rule for _, rule in rules_fired(events)}
    assert "high_connection_frequency" in fired


def test_suspicious_port_activity():
    events = [make(i * 10, port=4444, etype="connection", status="success") for i in range(3)]
    assert rules_fired(events) == {("203.0.113.5", "suspicious_port_activity")}


def test_thresholds_are_configurable():
    config = load_rules()
    config["rules"]["failed_login_bruteforce"]["threshold"] = 3
    events = [make(i * 5) for i in range(3)]
    assert DetectionEngine(config).analyze(events)[0].rule == "failed_login_bruteforce"


def test_disabled_rule_does_not_fire():
    config = load_rules()
    config["rules"]["failed_login_bruteforce"]["enabled"] = False
    assert DetectionEngine(config).analyze([make(i) for i in range(10)]) == []


def test_sources_are_analysed_independently():
    events = [make(i, src="203.0.113.5") for i in range(2)] + [make(i, src="203.0.113.6") for i in range(2)]
    assert rules_fired(events) == set()  # 2+2 failures must not be added together


def test_default_scenario_matches_ground_truth():
    scenario = generate_scenario(seed=42, base_time=T0)
    from app.services.detection_engine import EventRecord as ER
    records = [
        ER(source_ip=e.source_ip, destination_ip=e.destination_ip, destination_port=e.destination_port,
           protocol=e.protocol, event_type=e.event_type, connection_status=e.connection_status,
           connection_attempts=e.connection_attempts, timestamp=e.timestamp)
        for e in scenario.events
    ]
    assert rules_fired(records) == scenario.expected


def test_benign_traffic_produces_no_detections_across_seeds():
    for seed in range(20):
        events = generate_benign(random.Random(seed), T0)
        records = [
            EventRecord(source_ip=e.source_ip, destination_ip=e.destination_ip,
                        destination_port=e.destination_port, protocol=e.protocol, event_type=e.event_type,
                        connection_status=e.connection_status, connection_attempts=e.connection_attempts,
                        timestamp=e.timestamp)
            for e in events
        ]
        assert rules_fired(records) == set(), f"false positive with seed {seed}"

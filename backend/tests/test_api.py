"""API integration tests against a real PostgreSQL test database."""
from datetime import datetime, timedelta, timezone


def event(ts, src="203.0.113.50", dst="10.0.0.5", dport=22, etype="login_attempt", status="failed", attempts=1):
    return {
        "source_ip": src, "destination_ip": dst, "source_port": 50000, "destination_port": dport,
        "protocol": "TCP", "timestamp": ts.isoformat(), "event_type": etype,
        "connection_status": status, "connection_attempts": attempts,
    }


def brute_force_batch(src="203.0.113.50", n=8):
    t = datetime.now(timezone.utc) - timedelta(minutes=2)
    return {"events": [event(t + timedelta(seconds=i * 3), src=src) for i in range(n)]}


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok", "database": "connected"}


def test_single_event_ingestion_and_listing(client):
    r = client.post("/api/events", json=event(datetime.now(timezone.utc), status="success", etype="connection"))
    assert r.status_code == 201
    assert r.json()["events_ingested"] == 1 and r.json()["incidents_created"] == 0
    events = client.get("/api/events").json()
    assert len(events) == 1 and events[0]["source_ip"] == "203.0.113.50"
    assert "timestamp" in events[0]


def test_invalid_events_are_rejected(client):
    bad_ip = event(datetime.now(timezone.utc), src="999.1.1.1")
    assert client.post("/api/events", json=bad_ip).status_code == 422
    bad_port = event(datetime.now(timezone.utc), dport=70000)
    assert client.post("/api/events", json=bad_port).status_code == 422
    bad_proto = {**event(datetime.now(timezone.utc)), "protocol": "XYZ"}
    assert client.post("/api/events", json=bad_proto).status_code == 422
    assert client.post("/api/events/batch", json={"events": []}).status_code == 422
    assert client.get("/api/events").json() == []


def test_batch_with_one_invalid_event_stores_nothing(client):
    batch = brute_force_batch()
    batch["events"].append(event(datetime.now(timezone.utc), src="not-an-ip"))
    assert client.post("/api/events/batch", json=batch).status_code == 422
    assert client.get("/api/events").json() == []


def test_batch_creates_incident_automatically(client):
    r = client.post("/api/events/batch", json=brute_force_batch())
    assert r.status_code == 201
    body = r.json()
    assert body["events_ingested"] == 8 and body["incidents_created"] == 1
    incident = client.get(f"/api/incidents/{body['incident_ids'][0]}").json()
    assert incident["threat_category"] == "Brute Force Attack"
    assert incident["status"] == "Open" and incident["severity"] == "High"
    assert incident["evidence"]["failed_attempts"] == 8
    assert incident["source_ip"] == "203.0.113.50"


def test_duplicate_detection_is_deduplicated_while_incident_open(client):
    client.post("/api/events/batch", json=brute_force_batch())
    second = client.post("/api/events/batch", json=brute_force_batch()).json()
    assert second["incidents_created"] == 0 and second["incidents_deduplicated"] == 1
    assert len(client.get("/api/incidents").json()) == 1


def test_resolved_incident_is_not_reopened_by_old_events_but_new_attack_creates_new_one(client):
    first = client.post("/api/events/batch", json=brute_force_batch()).json()
    iid = first["incident_ids"][0]
    client.patch(f"/api/incidents/{iid}/status", json={"status": "Resolved"})
    # an unrelated benign event from the same IP must not re-trigger detection on old events
    benign = event(datetime.now(timezone.utc), status="success", etype="connection", dport=443)
    assert client.post("/api/events", json=benign).json()["incidents_created"] == 0
    # a fresh attack wave does create a new incident
    again = client.post("/api/events/batch", json=brute_force_batch()).json()
    assert again["incidents_created"] == 1


def test_status_update_and_audit_log(client):
    iid = client.post("/api/events/batch", json=brute_force_batch()).json()["incident_ids"][0]
    r = client.patch(f"/api/incidents/{iid}/status", json={"status": "Investigating", "actor": "alice"})
    assert r.status_code == 200 and r.json()["status"] == "Investigating"
    detail = client.get(f"/api/incidents/{iid}").json()
    actions = [(a["action"], a["actor"]) for a in detail["audit_logs"]]
    assert ("incident_created", "detection_engine") in actions
    assert ("status_changed", "alice") in actions
    change = next(a for a in detail["audit_logs"] if a["action"] == "status_changed")
    assert change["details"] == {"from": "Open", "to": "Investigating"}


def test_invalid_status_rejected_and_missing_incident_404(client):
    iid = client.post("/api/events/batch", json=brute_force_batch()).json()["incident_ids"][0]
    assert client.patch(f"/api/incidents/{iid}/status", json={"status": "Closed"}).status_code == 422
    assert client.patch("/api/incidents/9999/status", json={"status": "Resolved"}).status_code == 404
    assert client.get("/api/incidents/9999").status_code == 404
    assert client.post("/api/incidents/9999/notes", json={"note": "x"}).status_code == 404


def test_notes_are_stored_and_audited(client):
    iid = client.post("/api/events/batch", json=brute_force_batch()).json()["incident_ids"][0]
    r = client.post(f"/api/incidents/{iid}/notes", json={"note": "  Checked auth logs  ", "author": "bob"})
    assert r.status_code == 201 and r.json()["note"] == "Checked auth logs"
    assert client.post(f"/api/incidents/{iid}/notes", json={"note": "   "}).status_code == 422
    detail = client.get(f"/api/incidents/{iid}").json()
    assert [n["author"] for n in detail["notes"]] == ["bob"]
    assert any(a["action"] == "note_added" for a in detail["audit_logs"])


def test_filters_by_severity_and_status(client):
    client.post("/api/events/sample")
    all_incidents = client.get("/api/incidents").json()
    assert len(all_incidents) == 6
    high = client.get("/api/incidents", params={"severity": "High"}).json()
    assert high and all(i["severity"] == "High" for i in high)
    assert client.get("/api/incidents", params={"severity": "Nope"}).status_code == 422
    client.patch(f"/api/incidents/{all_incidents[0]['id']}/status", json={"status": "False Positive"})
    fp = client.get("/api/incidents", params={"status": "False Positive"}).json()
    assert len(fp) == 1
    both = client.get("/api/incidents", params={"status": "Open", "severity": all_incidents[1]["severity"]}).json()
    assert all(i["status"] == "Open" for i in both)


def test_sample_scenario_creates_expected_incidents_and_stats(client):
    r = client.post("/api/events/sample").json()
    assert r["incidents_created"] == 6
    rules = {i["detection_rule"] for i in client.get("/api/incidents").json()}
    assert rules == {"failed_login_bruteforce", "port_scan_pattern", "high_connection_frequency",
                     "suspicious_port_activity", "repeated_connections", "unusual_destination_port"}
    iid = client.get("/api/incidents", params={"severity": "High"}).json()[0]["id"]
    client.patch(f"/api/incidents/{iid}/status", json={"status": "Resolved"})
    stats = client.get("/api/dashboard/stats").json()
    assert stats["total_events"] == r["events_ingested"]
    assert stats["total_incidents"] == 6
    assert sum(stats["severity_distribution"].values()) == 6
    assert stats["resolved_incidents"] == 1 and stats["open_incidents"] == 5
    assert len(stats["recent_events"]) == 10

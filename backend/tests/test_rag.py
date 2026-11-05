"""RAG tests: retrieval (no LLM), template fallback labelling, and the LLM path with a fake provider."""
import pytest

from app.config import get_settings
from app.services import rag_service
from app.services.llm import LLMError


@pytest.fixture(autouse=True)
def no_real_llm(monkeypatch):
    """Never call a real LLM from tests, whatever is in the developer's environment."""
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("LLM_MODEL", "")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture()
def incidents(client):
    client.post("/api/events/sample")
    return {i["detection_rule"]: i for i in client.get("/api/incidents").json()}


def test_knowledge_is_seeded_and_seed_is_idempotent(client):
    docs = client.get("/api/knowledge").json()
    assert len(docs) == 10
    again = client.post("/api/knowledge/seed").json()
    assert again == {"inserted": 0, "updated": 0, "total": 10}


def test_seed_recreates_missing_documents(client):
    from sqlalchemy import text
    from app.database import engine
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM knowledge_documents"))
    assert client.get("/api/knowledge").json() == []
    assert client.post("/api/knowledge/seed").json()["inserted"] == 10


def test_full_text_search_endpoint(client):
    hits = client.get("/api/knowledge/search", params={"q": "port scan"}).json()
    assert hits and hits[0]["slug"] == "port-scanning"
    assert hits[0]["relevance_score"] > 0 and hits[0]["snippet"]
    assert client.get("/api/knowledge/search", params={"q": "zzzqqq"}).json() == []
    assert client.get("/api/knowledge/search", params={"q": "a"}).status_code == 422


def test_search_input_is_sanitised(client):
    # tsquery metacharacters must not cause a SQL/tsquery syntax error
    r = client.get("/api/knowledge/search", params={"q": "'; DROP TABLE incidents; -- & | ! ( )"})
    assert r.status_code == 200
    assert client.get("/api/incidents").status_code == 200


EXPECTED_TOP_DOC = {
    "failed_login_bruteforce": "brute-force-attacks",
    "port_scan_pattern": "port-scanning",
    "high_connection_frequency": "denial-of-service-attacks",
    "suspicious_port_activity": "suspicious-port-activity",
    "repeated_connections": "connection-anomalies-and-unusual-ports",
    "unusual_destination_port": "connection-anomalies-and-unusual-ports",
}


def test_retrieval_ranks_the_relevant_playbook_first_for_every_rule(client, incidents):
    for rule, slug in EXPECTED_TOP_DOC.items():
        report = client.post(f"/api/ai/investigate/{incidents[rule]['id']}").json()
        got = [d["slug"] for d in report["retrieved_documents"]]
        assert got[0] == slug, f"{rule}: expected {slug} first, got {got}"


def test_fallback_report_is_clearly_labelled_and_structured(client, incidents):
    iid = incidents["failed_login_bruteforce"]["id"]
    r = client.post(f"/api/ai/investigate/{iid}")
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "fallback"
    assert body["generated_by"] == "template (no LLM used)"
    assert "ANTHROPIC_API_KEY is not set" in body["fallback_reason"]
    md = body["report_markdown"]
    assert "NOT AI-GENERATED" in md
    for heading in rag_service.REPORT_SECTIONS:
        assert f"## {heading}" in md
    assert "203.0.113.10" in md and "[KB: brute-force-attacks]" in md
    assert "human approval" in body["approval_notice"]
    assert "Observed" in md and "Assessment" in md


def test_investigation_does_not_modify_the_incident_and_is_audited(client, incidents):
    inc = incidents["port_scan_pattern"]
    client.post(f"/api/ai/investigate/{inc['id']}")
    detail = client.get(f"/api/incidents/{inc['id']}").json()
    assert detail["status"] == "Open" and detail["severity"] == inc["severity"]
    assert any(a["action"] == "ai_investigation" for a in detail["audit_logs"])


def test_unknown_incident_returns_404(client):
    assert client.post("/api/ai/investigate/9999").status_code == 404


class FakeProvider:
    name, model = "fake", "fake-model-1"

    def __init__(self):
        self.system = self.user = None

    def generate(self, system, user):
        self.system, self.user = system, user
        return "## 1. Incident Summary\nLLM text"


def test_llm_path_sends_incident_evidence_and_documents(client, incidents, monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(rag_service, "get_provider", lambda: fake)
    inc = incidents["port_scan_pattern"]
    client.post(f"/api/incidents/{inc['id']}/notes", json={"note": "Checked firewall", "author": "dana"})
    body = client.post(f"/api/ai/investigate/{inc['id']}").json()
    assert body["mode"] == "llm" and body["generated_by"] == "fake:fake-model-1"
    assert body["fallback_reason"] is None and "NOT AI-GENERATED" not in body["report_markdown"]
    assert "198.51.100.23" in fake.user and "distinct_ports" in fake.user       # incident + evidence
    assert "[KB: port-scanning]" in fake.user and "Checked firewall" in fake.user  # context + notes
    assert "Never invent" in fake.system and "human approval" in fake.system


def test_llm_failure_falls_back_with_reason_and_label(client, incidents, monkeypatch):
    class Broken:
        name, model = "x", "y"

        def generate(self, system, user):
            raise LLMError("LLM API returned HTTP 529")

    monkeypatch.setattr(rag_service, "get_provider", lambda: Broken())
    body = client.post(f"/api/ai/investigate/{incidents['failed_login_bruteforce']['id']}").json()
    assert body["mode"] == "fallback" and "HTTP 529" in body["fallback_reason"]
    assert "NOT AI-GENERATED" in body["report_markdown"]

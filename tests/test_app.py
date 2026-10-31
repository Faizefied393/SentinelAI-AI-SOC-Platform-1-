import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.agent import run_tool
from app.db import connect

client = TestClient(app)

def test_health():
    assert client.get("/health").json() == {"status": "ok"}

def test_import_and_detection():
    payload = json.loads(Path("sample_data/suspicious_events.json").read_text())
    response = client.post("/events/import", json=payload)
    assert response.status_code == 200
    assert response.json()["imported"] == 7
    alerts = client.get("/alerts").json()
    assert any(a["technique"] == "T1110" for a in alerts)
    assert any(a["technique"] == "T1059.001" for a in alerts)

def test_invalid_time():
    event = {"events": [{"timestamp": "2026-10-26T12:00:00", "host": "x", "provider": "x", "event_type": "auth_failure"}]}
    assert client.post("/events/import", json=event).status_code == 422

def test_tool_denied():
    with pytest.raises(PermissionError):
        run_tool("execute_shell", {"command": "echo hi"})
    with connect() as db:
        assert db.execute("SELECT COUNT(*) FROM audit WHERE action='tool_denied'").fetchone()[0] == 1

def test_bad_cve():
    assert client.get("/intelligence/not-a-cve").status_code == 400

def test_evidence_reference_rejection(monkeypatch):
    payload = json.loads(Path("sample_data/suspicious_events.json").read_text())
    client.post("/events/import", json=payload)
    import app.agent as agent
    class FakeResponse:
        def raise_for_status(self): pass
        def json(self):
            return {"message": {"content": json.dumps({
                "summary":"Test","evidence_event_ids":[999999],
                "hypotheses":[],"alternative_explanations":[],
                "next_steps":[],"limitations":[]
            })}}
    monkeypatch.setattr(agent, "_chat", lambda *args, **kwargs: {"content": FakeResponse().json()["message"]["content"]})
    alert_id = client.get("/alerts").json()[0]["id"]
    response = client.post(f"/alerts/{alert_id}/investigate")
    assert response.status_code == 400
    assert client.get("/investigations").json() == []

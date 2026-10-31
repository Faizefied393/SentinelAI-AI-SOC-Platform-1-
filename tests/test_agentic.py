import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.agent import run_tool

client = TestClient(app)

def _seed():
    data = json.loads(Path("sample_data/suspicious_events.json").read_text())
    client.post("/events/import", json=data)
    return client.get("/alerts").json()[0]["id"]

def test_scope_enforcement():
    alert_id = _seed()
    with pytest.raises(PermissionError):
        run_tool("get_events", {"alert_id": alert_id+100}, scoped_alert_id=alert_id)

def test_agent_calls_tools_and_generates_report(monkeypatch):
    alert_id = _seed()
    from app import agent
    count = {"n": 0}
    def fake_chat(messages, *, tools=None, schema=None, timeout=90):
        if tools is not None:
            count["n"] += 1
            if count["n"] == 1:
                return {"content": "", "tool_calls": [{"function": {"name": "get_events", "arguments": {"alert_id": alert_id}}}]}
            return {"content": "done"}
        with agent.connect() as db:
            row = db.execute("SELECT event_ids FROM alerts WHERE id=?", (alert_id,)).fetchone()
        ids = json.loads(row["event_ids"])
        return {"content": json.dumps({"summary":"Repeated failures observed", "evidence_event_ids":ids, "hypotheses":["Password guessing"], "alternative_explanations":["Stale credentials"], "next_steps":["Review source"], "limitations":["Synthetic lab data"]})}
    monkeypatch.setattr(agent, "_chat", fake_chat)
    report = agent.investigate(alert_id)
    assert report["tool_trace"][0] == {"tool":"get_events", "status":"ok"}
    assert report["requires_analyst_review"] is True
    assert set(report["evidence_event_ids"]) == set(report["verified_event_ids"])

def test_malicious_log_text_cannot_authorize_shell(monkeypatch):
    alert_id = _seed()
    from app import agent
    count = {"n": 0}
    def fake_chat(messages, *, tools=None, schema=None, timeout=90):
        if tools is not None:
            count["n"] += 1
            if count["n"] == 1:
                return {"tool_calls": [{"function": {"name":"execute_shell", "arguments":{"command":"echo dangerous"}}}]}
            return {"content":"stop"}
        return {"content": json.dumps({"summary":"No unauthorized action performed", "evidence_event_ids":[], "hypotheses":[], "alternative_explanations":[], "next_steps":[], "limitations":["No supporting evidence cited"]})}
    monkeypatch.setattr(agent, "_chat", fake_chat)
    result = agent.investigate(alert_id)
    assert result["tool_trace"][0]["status"] == "denied"

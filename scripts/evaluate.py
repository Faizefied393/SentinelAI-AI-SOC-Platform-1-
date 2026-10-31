"""Reproducible deterministic baseline evaluation, not an LLM accuracy benchmark."""
import json
import os
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.db import init_db

with tempfile.TemporaryDirectory() as temp:
    os.environ["SENTINEL_DB"] = str(Path(temp) / "evaluation.db")
    init_db()
    client = TestClient(app)
    data = json.loads(Path("sample_data/suspicious_events.json").read_text())
    imported = client.post("/events/import", json=data)
    alerts = client.get("/alerts").json()
    techniques = {a["technique"] for a in alerts}
    metrics = {
        "scenario": "synthetic_suspicious_events",
        "events_imported": imported.json()["imported"],
        "alerts_created": len(alerts),
        "expected_techniques_found": sorted(techniques & {"T1110", "T1059.001"}),
        "expected_technique_recall": len(techniques & {"T1110", "T1059.001"}) / 2,
        "note": "Only a deterministic smoke evaluation; not model precision/recall on real incidents."
    }
    print(json.dumps(metrics, indent=2))

import json
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel, Field, field_validator
from app.db import connect, init_db, audit
from app.detection import detect
from app.agent import investigate, run_tool

app = FastAPI(title="SentinelAI Enterprise - Local Lab", version="1.0")
init_db()

class Event(BaseModel):
    timestamp: datetime
    host: str = Field(min_length=1, max_length=100)
    provider: str = Field(min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=100)
    source_ip: str | None = Field(default=None, max_length=45)
    username: str | None = Field(default=None, max_length=100)
    details: dict = Field(default_factory=dict)
    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Timestamp must contain timezone")
        return value.astimezone(timezone.utc)

class EventBatch(BaseModel):
    events: list[Event] = Field(min_length=1, max_length=500)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/events/import")
def import_events(batch: EventBatch):
    with connect() as db:
        for e in batch.events:
            db.execute(
                "INSERT INTO events(timestamp,host,provider,event_type,source_ip,username,details) VALUES(?,?,?,?,?,?,?)",
                (e.timestamp.isoformat(), e.host, e.provider, e.event_type,
                 e.source_ip, e.username, json.dumps(e.details))
            )
    created = detect()
    audit("import", {"count": len(batch.events), "new_alerts": created})
    return {"imported": len(batch.events), "new_alerts": created}

@app.get("/events")
def events():
    with connect() as db:
        return [dict(r) for r in db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 200")]

@app.get("/alerts")
def alerts():
    with connect() as db:
        return [dict(r) for r in db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100")]

@app.post("/alerts/{alert_id}/investigate")
def investigate_endpoint(alert_id: int):
    try:
        return investigate(alert_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

@app.get("/investigations")
def investigations():
    with connect() as db:
        return [dict(r) for r in db.execute("SELECT * FROM investigations ORDER BY id DESC LIMIT 100")]

@app.get("/intelligence/{cve}")
def intelligence(cve: str):
    try:
        return run_tool("lookup_cve", {"cve": cve})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

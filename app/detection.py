import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from app.db import connect

def detect():
    """Recompute rules for the small local lab; deduplicate by title and evidence."""
    with connect() as db:
        rows = [dict(r) for r in db.execute("SELECT * FROM events ORDER BY timestamp, id")]
        existing = {(r["title"], r["event_ids"]) for r in db.execute("SELECT title,event_ids FROM alerts")}
        findings = []
        groups = defaultdict(list)
        for row in rows:
            if row["event_type"] == "auth_failure":
                groups[(row["host"], row["username"], row["source_ip"])].append(row)
            if row["event_type"] == "process_creation":
                details = json.loads(row["details"])
                cmd = str(details.get("command_line", "")).lower()
                if any(x in cmd for x in ("-enc ", "encodedcommand", "frombase64string")):
                    findings.append(("Suspicious encoded PowerShell command", "medium", [row["id"]], "T1059.001"))
        for (host, user, ip), group in groups.items():
            for i in range(len(group)):
                start = datetime.fromisoformat(group[i]["timestamp"].replace("Z", "+00:00"))
                window = []
                for r in group[i:]:
                    t = datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00"))
                    if t - start <= timedelta(minutes=5):
                        window.append(r["id"])
                    else:
                        break
                if len(window) >= 5:
                    # Record one finding for the earliest qualifying window per group.
                    findings.append((f"Repeated failed logins: {user}@{host} from {ip}", "high", window, "T1110"))
                    break
        created = 0
        for title, severity, ids, technique in findings:
            ids_json = json.dumps(ids)
            if (title, ids_json) not in existing:
                db.execute(
                    "INSERT INTO alerts(title,severity,event_ids,technique) VALUES(?,?,?,?)",
                    (title, severity, ids_json, technique)
                )
                existing.add((title, ids_json))
                created += 1
        return created

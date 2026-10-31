# SentinelAI Enterprise — Agentic SOC & AI Security Validation

A local, defensive cybersecurity engineering portfolio application with **bounded LLM tool calling**, security event ingestion, ATT&CK-tagged detection rules, threat intelligence, evidence-linked reporting, audit logging, and adversarial tests.

## What is included

- FastAPI + SQLite event/alert/investigation persistence
- JSON security event import and two detection rules (T1110 and T1059.001)
- Ollama tool-calling agent with five allowlisted read-only tools, per-alert scope, tool-call budget and audit logging
- Structured LLM report with event-ID validation and analyst review flag
- CISA KEV + FIRST EPSS lookups (not full NVD/CVSS enrichment)
- Streamlit dashboard
- Pytest tests, deterministic smoke evaluation, Docker Compose, GitHub Actions

## Install (Windows 11 + WSL Ubuntu 24.04)

1. In admin PowerShell: `wsl --install -d Ubuntu-24.04` (if not installed).
2. In Ubuntu: `sudo apt update && sudo apt install -y python3.12 python3.12-venv git curl unzip`.
3. Install VS Code, Docker Desktop (optional), and Ollama on Windows.
4. In Windows PowerShell: `ollama pull llama3.2:3b`.
5. Extract the project ZIP into a folder and `cd` into it.
6. `python3.12 -m venv .venv && source .venv/bin/activate`
7. `python -m pip install -r requirements.txt`
8. `python -m pytest -q`
9. Terminal A: `uvicorn app.main:app --reload --host 127.0.0.1`
10. Terminal B: `streamlit run app/dashboard.py --server.address 127.0.0.1`
11. Open `http://127.0.0.1:8501`.

## Reproduce a full investigation

```bash
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/events/import -H 'Content-Type: application/json' --data-binary @sample_data/suspicious_events.json
curl http://127.0.0.1:8000/alerts
curl -X POST http://127.0.0.1:8000/alerts/1/investigate
curl http://127.0.0.1:8000/investigations
curl http://127.0.0.1:8000/intelligence/CVE-2021-44228
```

If the first alert ID is not 1, use the ID returned by `/alerts`. You can also import the sample JSON using the dashboard.

## Tests and evaluation

```bash
python -m pytest -q
python -m scripts.evaluate
# Requires running Ollama; performs two real-model investigations:
python -m scripts.evaluate_llm
```

Tests include invalid input, detection, scope enforcement, unauthorized tool denial, fabricated evidence rejection, and a mocked agent tool-call loop. **Mocked agent tests do not prove real-model prompt-injection resistance.**

## Docker

Stop local API/dashboard processes and run `docker compose up --build -d`. Check `docker compose ps` and `docker compose logs api`. Windows Ollama must be reachable by Docker through `host.docker.internal:11434`; this may require host network configuration. Do not expose Ollama on public interfaces.

## Architecture

JSON logs → FastAPI validation → SQLite → deterministic detection → alerts → bounded Ollama tool-calling loop → deterministic evidence retrieval → schema-validated LLM report → analyst review. Tool calls are audited and scoped to one alert. CVE lookup is a separate read-only enrichment capability.

## Security boundaries and limitations

- **LOCAL LAB ONLY.** The app has no authentication or rate limiting. Never expose the API or dashboard to untrusted networks. The dashboard does not enforce user identity.
- Uploaded JSON size is limited by the dashboard UI, not at the API gateway; use small synthetic files only. The API caps batches at 500 events.
- No autonomous remediation or arbitrary shell execution is implemented. Tool names and arguments are validated in Python.
- Model-selected tools are allowed, but a model can still produce misleading prose. Only evidence event IDs are mechanically verified; analyst review is mandatory.
- External threat intelligence is best effort and may be unavailable; KEV/EPSS results are not proof that an asset is vulnerable.
- The detection rules are simple and can produce false positives. The sample dataset is synthetic, not a real-world detection benchmark.
- A real-world deployment needs authentication, rate limiting, data redaction, proper sandboxing, concurrency controls, migration tooling, secret management, dependency pinning, and systematic LLM red-team evaluation.

## Portfolio next steps

1. Run 20–30 real-model prompt-injection tests and record attack success rate.
2. Add a labeled SOC scenario set with precision, recall, and false-positive analysis.
3. Add document retrieval with source citations and retrieval-quality evaluation.
4. Add NVD/CVSS enrichment and verified asset context.
5. Add authentication and structured analyst approval workflows.

See `docs/FINAL_CHECKLIST.md` for the demonstration checklist and known limitations.

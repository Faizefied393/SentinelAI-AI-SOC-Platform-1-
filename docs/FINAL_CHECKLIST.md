# SentinelAI completion and demonstration checklist

## Reproducible core (implemented)
- [ ] Python 3.12 environment and dependencies installed
- [ ] `python -m pytest -q` passes
- [ ] `python -m scripts.evaluate` prints synthetic smoke evaluation
- [ ] API health endpoint returns `ok`
- [ ] Sample JSON import creates two ATT&CK-tagged alerts
- [ ] Ollama model is available and real investigation returns a report
- [ ] Agent tool trace shows at least one tool call (model behavior may vary)
- [ ] Fake tool request is denied by backend (automated test)
- [ ] Fabricated evidence IDs are rejected (automated test)
- [ ] CISA KEV/EPSS lookup works or reports upstream errors
- [ ] Streamlit dashboard displays results
- [ ] Docker Compose runs API and dashboard locally
- [ ] GitHub Actions tests pass after pushing repository

## Evidence for portfolio
Capture: screenshot of alert list; AI report and tool trace; denied-tool test result; `pytest` output; smoke evaluation output; Docker containers; architecture diagram.

## Research-quality enhancements (not implemented)
- Real LLM prompt-injection benchmark with pass/fail ground truth
- Actual retrieval-augmented generation over a document corpus
- ML anomaly model and labeled detection metrics
- Full NVD CVSS enrichment and verified asset inventory
- Authentication, permissions by user, data-loss prevention and deployment hardening

Do not describe these enhancements as completed until implemented and tested.

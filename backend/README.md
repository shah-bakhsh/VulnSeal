# 🛡️ VulnSeal Autonomous Security Remediation — Python Backend

Complete autonomous cybersecurity vulnerability scanning and remediation platform backend written in Python 3.

## 🚀 Quick Start

### Option 1: Zero-Dependency Standard Library Runner (Out-of-the-Box)
You can run the Python backend immediately with native Python 3 (no pip installations required):

```bash
python3 -m backend.main
```
The server will start listening at `http://localhost:8000`.

### Option 2: Modern FastAPI / Uvicorn ASGI Server
```bash
pip install -r backend/requirements.txt
uvicorn backend.fastapi_app:app --host 0.0.0.0 --port 8000 --reload
```

---

## 🏛️ Architecture & Modules

* **`backend/main.py`**: Standard library HTTP REST API server with full endpoint parity.
* **`backend/fastapi_app.py`**: FastAPI / ASGI application entrypoint.
* **`backend/scanner.py`**: Multi-agent vulnerability scanner orchestrating `ScopeGuard`, `SurfaceMapper`, `SecurityInspector`, and `EvidenceJudge`.
* **`backend/ai_router.py`**: Multi-LLM provider router (Groq Cloud Llama 3.3 70B, Google Gemini Flash, and deterministic AST engine).
* **`backend/shadowfix.py`**: Digital-twin sandbox with automated patch application, regression testing, and cryptographic SHA-256 Proof-of-Fix certificates.
* **`backend/policy.py`**: ScopeGuard firewall preventing SSRF, private network abuse, and unverified targets.
* **`backend/demo_target.py`**: Self-contained vulnerable banking sandbox for live remediation demonstrations.
* **`backend/rules/`**:
  * `headers_rule.py`: HSTS, CSP, X-Frame-Options, X-Content-Type-Options inspector.
  * `cors_rule.py`: Permissive CORS origin and credential validator.
  * `cookie_rule.py`: Secure, HttpOnly, and SameSite cookie attribute inspector.
* **`backend/db.py`**: State repository for workspaces, targets, scans, findings, proofs, and audit logs.
* **`backend/supabase_client.py`**: PostgreSQL / Supabase client connector.

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/workspaces` | Retrieve all workspaces |
| `GET` / `POST` | `/api/targets` | List or register scan targets |
| `GET` / `POST` | `/api/scans` | List or initiate scans |
| `GET` | `/api/findings` | List confirmed vulnerabilities |
| `POST` | `/api/remediations/generate` | Generate root-cause analysis and unified diff patch |
| `POST` | `/api/remediations/approve` | Human approval of patch diff |
| `POST` | `/api/shadowfix/run` | Execute digital-twin replay and issue Proof-of-Fix |
| `GET` | `/api/proofs` | List cryptographic Proof-of-Fix records |
| `GET` | `/api/agents/events` | Stream multi-agent event logs |
| `GET` | `/api/audit-logs` | Immutable audit trail |
| `GET` | `/demo-target` | Live vulnerable sandbox web interface |

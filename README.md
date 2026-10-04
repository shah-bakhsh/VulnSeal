<div align="center">

# 🛡️ VulnSeal

### Autonomous Security Remediation & Cryptographic Proof Platform

<p align="center">
  <strong>Find. Fix. Prove.</strong><br>
  <em>Autonomous cybersecurity vulnerability scanning and remediation platform with verified cryptographic proof.</em>
</p>

[![CI Pipeline](https://img.shields.io/badge/CI-Passing-emerald?style=flat-square&logo=githubactions)](https://github.com)
[![Node.js](https://img.shields.io/badge/Node.js-v20+-339933?style=flat-square&logo=nodedotjs)](https://nodejs.org)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?style=flat-square&logo=typescript)](https://www.typescriptlang.org)
[![Vite](https://img.shields.io/badge/Vite-6.x-646CFF?style=flat-square&logo=vite)](https://vitejs.dev)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker)](https://docker.com)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](LICENSE)

</div>

---

## 📌 Table of Contents

- [Overview](#-overview)
- [The Problem vs. The VulnSeal Solution](#-the-problem-vs-the-vulnseal-solution)
- [Core Architecture & The 7 Specialized Agents](#-core-architecture--the-7-specialized-agents)
- [ShadowFix™ Digital Twin & Cryptographic Proof of Fix](#-shadowfix-digital-twin--cryptographic-proof-of-fix)
- [Quick Start](#-quick-start)
  - [Full-Stack Development (Node + Vite)](#1-full-stack-development-node-20--express--vite)
  - [Standalone Python Backend](#2-standalone-python-backend)
- [Automated Testing & Verification](#-automated-testing--verification)
- [Deploy & Host Online](#-deploy--host-online)
  - [Option A: One-Click Deploy to Render](#option-a-deploy-to-render)
  - [Option B: One-Click Deploy to Railway](#option-b-deploy-to-railway)
  - [Option C: Docker & Docker Compose](#option-c-docker--docker-compose)
  - [Option D: Linux VPS Deployment (Nginx + Systemd)](#option-d-linux-vps-deployment)
- [Environment Configuration](#-environment-configuration)
- [REST API Reference](#-rest-api-reference)
- [Security & ScopeGuard Isolation](#-security--scopeguard-isolation)
- [Brand Identity](#-brand-identity)
- [License](#-license)

---

## 💡 Overview

Traditional security tools stop after reporting a finding, leaving engineers with lengthy PDFs and guesswork. **VulnSeal** bridges the gap between vulnerability discovery and verified production repair:

```text
FIND (Deterministic Scanning) 
  → FIX (Root Cause & Minimal Patch Synthesis) 
    → PROVE (Isolated Sandbox Replay & SHA-256 Proof Certificate)
```

---

## ⚖️ The Problem vs. The VulnSeal Solution

| Traditional AST / DAST Scanners | 🛡️ VulnSeal Autonomous Remediation |
|---|---|
| Generates endless lists of noisy alerts | Strictly verifies evidence before confirming |
| Stops at "Here is a vulnerability" | Pinpoints the exact source code file, line, and AST symbol |
| Leaves developer to research and draft fixes | Synthesizes minimal, safe unified diffs (`.patch`) |
| Fixes applied blindly in production | Patches applied and replayed inside an isolated **ShadowFix** digital twin |
| No proof that the bug is resolved | Issues a tamper-evident **SHA-256 Cryptographic Proof of Fix Certificate** |

---

## 🤖 Core Architecture & The 7 Specialized Agents

VulnSeal employs a segregated multi-agent pipeline where each agent has strict boundaries:

```
[Target URL]
     │
     ▼
┌──────────────────┐
│  1. ScopeGuard   │ ──► Enforces origin authorization & blocks SSRF / internal networks
└────────┬─────────┘
         ▼
┌──────────────────┐
│ 2. SurfaceMapper │ ──► Crawls endpoints, parameters, and form inputs
└────────┬─────────┘
         ▼
┌───────────────────────────┐
│   3. SecurityInspector    │ ──► Executes deterministic inspection rules (CORS, CSP, Cookies, Headers)
└────────────┬──────────────┘
             ▼
┌───────────────────────────┐
│     4. EvidenceJudge      │ ──► Validates observed evidence against baseline false positives
└────────────┬──────────────┘
             ▼
┌───────────────────────────┐
│   5. RootCauseMapper      │ ──► Identifies repository source code file and line number
└────────────┬──────────────┘
             ▼
┌───────────────────────────┐
│  6. RemediationEngineer   │ ──► Synthesizes minimal unified diffs & regression test assertions
└────────────┬──────────────┘
             ▼
  [Human Operator Approval Gate]
             │
             ▼
┌───────────────────────────┐
│   7. IndependentVerifier  │ ──► Runs ShadowFix replay, executes test suite, and signs SHA-256 Proof
└───────────────────────────┘
```

---

## 🔒 ShadowFix™ Digital Twin & Cryptographic Proof of Fix

Before touching production code, every remediation candidate is tested in **ShadowFix**:
1. **Isolated Sandbox Twin**: Provisions an ephemeral execution container.
2. **Patch Application**: Applies the synthesized unified diff patch.
3. **Regression Suite**: Executes the test suite to ensure zero breaking changes.
4. **Security Replay**: Replays the original exploit vector to confirm the weakness is gone.
5. **Cryptographic Proof**: Computes a SHA-256 hash of the entire before/after evidence trail and issues a downloadable JSON certificate.

---

## 🚀 Quick Start

### 1. Automated Full-Stack Startup (Recommended)

#### Windows (PowerShell)
```powershell
.\scripts\dev.ps1
```

#### Linux / macOS (Bash)
```bash
chmod +x ./scripts/dev.sh
./scripts/dev.sh
```

---

### 2. Manual Step-by-Step Setup

#### Step A: Python 3.11+ FastAPI Backend
```bash
# 1. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1    # On Windows
# source .venv/bin/activate     # On Linux / macOS

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Start FastAPI ASGI server
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive OpenAPI documentation will be accessible at `http://127.0.0.1:8000/docs`.

#### Step B: React / TypeScript Frontend
In a separate terminal:
```bash
# 1. Install frontend dependencies
npm install

# 2. Start Vite development server
npm run dev
```
Open **`http://localhost:3000`** in your browser. All API requests are automatically proxied to the FastAPI backend.

---

## 🧪 Automated Testing & Verification

Run the full automated verification test suites across frontend and backend:

```bash
# 1. Python Pytest Test Suite (Policy, SSRF, Deterministic Rules, API & Workflow)
.\.venv\Scripts\pytest.exe -v

# 2. Python End-to-End Verification Loop (FIND -> FIX -> PROVE)
.\.venv\Scripts\python.exe -m backend.test_suite

# 3. TypeScript Security Gate Tests
npm test

# 4. TypeScript Typecheck & Production Vite Build
npm run lint
npm run build
```

---

## 🌐 Deploy & Host Online

### Option A: Deploy to Render (Full-Stack Continuous Web Service)

1. Push your repository to **GitHub**.
2. Log in to [Render](https://render.com) and click **New + > Web Service**.
3. Connect your repository. Render will automatically detect `render.yaml`.
4. Configure optional environment variables (`GROQ_API_KEY`, `GEMINI_API_KEY`, `SUPABASE_URL`) in the Render dashboard.
5. Click **Deploy**. Render will build and host your full-stack instance with zero-downtime health checking at `/api/workspaces`.

---

### Option B: Deploy to Vercel (Edge Frontend + Serverless API Functions)

1. Push your repository to **GitHub**.
2. Import the project in [Vercel](https://vercel.com/new).
3. Vercel will automatically detect Vite and `vercel.json`:
   * **Framework Preset**: Vite
   * **Build Command**: `npm run build`
   * **Output Directory**: `dist`
   * **Serverless Functions**: Handled automatically via `/api/index.ts`
4. Add your environment variables (`GROQ_API_KEY`, `GEMINI_API_KEY`, `SUPABASE_URL`) in **Project Settings &rarr; Environment Variables**.
5. Click **Deploy**.

---

### Option C: Deploy to Railway

1. Install the Railway CLI or connect via GitHub on [railway.app](https://railway.app).
2. Run:
   ```bash
   railway init
   railway up
   ```
3. Set your environment variables in the Railway dashboard.

---

### Option C: Docker & Docker Compose

Deploy on any server with Docker installed:

```bash
# Build and run container in detached mode
docker-compose up -d --build
```
Your instance will be live at `http://YOUR_SERVER_IP:3000`.

---

### Option D: Linux VPS Deployment (Ubuntu/Debian)

1. **Install Node.js & Nginx:**
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
   sudo apt-get install -y nodejs nginx git
   ```

2. **Clone & Build:**
   ```bash
   git clone https://github.com/your-username/vulnseal.git /var/www/vulnseal
   cd /var/www/vulnseal
   npm ci
   npm run build
   ```

3. **Configure Systemd Service (`/etc/systemd/system/vulnseal.service`):**
   ```ini
   [Unit]
   Description=VulnSeal Autonomous Security Platform
   After=network.target

   [Service]
   Type=simple
   User=www-data
   WorkingDirectory=/var/www/vulnseal
   ExecStart=/usr/bin/npx tsx server.ts
   Restart=on-failure
   Environment=NODE_ENV=production
   Environment=PORT=3000

   [Install]
   WantedBy=multi-user.target
   ```

4. **Start & Enable Service:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now vulnseal
   ```

---

## ⚙️ Environment Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

| Variable | Required | Description |
|---|---|---|
| `PORT` | No (Default `3000`) | Port for the HTTP server |
| `NODE_ENV` | No (`development` / `production`) | Runtime environment |
| `GROQ_API_KEY` | Optional | API key for high-speed Llama 3.3 70B inference |
| `GEMINI_API_KEY` | Optional | API key for Google Gemini reasoning models |
| `SUPABASE_URL` | Optional | Supabase PostgreSQL project URL for persistent cloud storage |
| `SUPABASE_ANON_KEY` | Optional | Supabase Anonymous or Service Role API key |

*(Note: VulnSeal features a 100% offline deterministic AST fallback engine; external API keys are optional).*

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/workspaces` | Retrieve configured workspace environments |
| `GET` / `POST` | `/api/targets` | List or register authorized targets |
| `POST` | `/api/targets/:id/verify` | Submit ScopeGuard ownership challenge proof |
| `GET` / `POST` | `/api/scans` | List historical scans or trigger a new multi-agent scan |
| `GET` | `/api/scans/:id` | Retrieve real-time progress and telemetry for a scan |
| `GET` | `/api/findings` | List all discovered and confirmed vulnerability records |
| `POST` | `/api/remediations/generate` | Trigger RootCauseMapper & synthesize code patch diff |
| `POST` | `/api/remediations/approve` | Human-in-the-loop patch approval gate |
| `POST` | `/api/shadowfix/run` | Execute digital-twin replay and compute Proof-of-Fix |
| `GET` | `/api/proofs` | List cryptographic Proof-of-Fix certificates |
| `GET` | `/api/proofs/:id/export` | Export signed proof certificate JSON |
| `GET` | `/api/agents/events` | Stream live multi-agent journal events |
| `GET` | `/api/audit-logs` | Retrieve tamper-resistant audit logs |
| `GET` | `/demo-target` | Access the built-in vulnerable sandbox application |

---

## 🛡️ Security & ScopeGuard Isolation

* **SSRF Firewall**: ScopeGuard verifies all outbound scan requests against private RFC 1918 networks, loopback addresses (`127.0.0.1`), and AWS metadata services (`169.254.169.254`).
* **Sandbox Digital Twin**: All candidate patches are executed inside isolated sandboxes before developer sign-off.
* **Non-Destructive Scanning**: SecurityInspector rules execute read-only observation queries without destructive side effects.

---

## 🎨 Brand Identity

* **Official Name**: VulnSeal
* **Tagline**: *Find. Fix. Prove.*
* **Mission**: Autonomous security remediation with verified proof.
* **Palette**:
  * **Primary Blue**: `#2563EB`
  * **Deep Blue**: `#1D4ED8`
  * **Electric Cyan**: `#38BDF8`
  * **Dark Charcoal**: `#0F172A`

---

## 📄 License

This project is licensed under the [Apache-2.0 License](LICENSE).

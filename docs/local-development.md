# 🛠️ VulnSeal Local Development Guide

## Overview
VulnSeal runs as a standalone full-stack platform:
- **Frontend**: React 19, TypeScript, Vite, Tailwind CSS (port 3000)
- **Backend**: Python 3.11+, FastAPI, SQLAlchemy, SQLite (port 8000)

---

## Prerequisites
- Node.js v20+ / npm 10+
- Python 3.11+

---

## Quick Start (Automated)

### Windows (PowerShell)
```powershell
.\scripts\dev.ps1
```

### Linux / macOS (Bash)
```bash
chmod +x ./scripts/dev.sh
./scripts/dev.sh
```

---

## Manual Step-by-Step Setup

### 1. Python FastAPI Backend
```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # Windows PowerShell
# or: source .venv/bin/activate # Linux / macOS

# Install Python requirements
pip install -r backend/requirements.txt

# Start FastAPI server
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
The FastAPI Swagger documentation will be available at `http://127.0.0.1:8000/docs`.

### 2. React / TypeScript Frontend
In a separate terminal:
```powershell
# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```
Open **`http://localhost:3000`** in your browser. All `/api` requests are automatically proxied to the Python backend on `http://127.0.0.1:8000`.

---

## Verification & Testing

### Python Test Suite (Pytest)
```powershell
.\.venv\Scripts\pytest.exe -v
```

### Python End-to-End Verification Loop
```powershell
.\.venv\Scripts\python.exe -m backend.test_suite
```

### TypeScript Security Tests & Typecheck
```powershell
npm test
npm run lint
npm run build
```

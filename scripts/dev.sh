#!/usr/bin/env bash
# VulnSeal Local Development Runner (Bash)

set -e

echo "=========================================================="
echo "🛡️  VULNSEAL AUTONOMOUS SECURITY PLATFORM (LOCAL RUNNER)"
echo "    Find. Fix. Prove."
echo "=========================================================="

VENV_PYTHON="./.venv/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
    echo "Creating Python virtual environment in .venv..."
    python3 -m venv .venv
    ./.venv/bin/pip install --upgrade pip
    ./.venv/bin/pip install -r backend/requirements.txt
fi

echo "Starting Python FastAPI Backend on http://127.0.0.1:8000..."
./.venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!

trap "echo 'Stopping Python Backend...'; kill $BACKEND_PID 2>/dev/null || true; exit" SIGINT SIGTERM EXIT

sleep 2

echo "Starting Frontend Vite Server on http://localhost:3000..."
npm run dev

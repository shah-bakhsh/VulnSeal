# VulnSeal Local Development Runner (PowerShell)
# Starts both Python FastAPI backend and Vite React frontend

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "🛡️  VULNSEAL AUTONOMOUS SECURITY PLATFORM (LOCAL RUNNER)" -ForegroundColor Cyan
Write-Host "    Find. Fix. Prove." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$VENV_PYTHON = ".\.venv\Scripts\python.exe"

if (-not (Test-Path $VENV_PYTHON)) {
    Write-Host "Virtual environment not detected. Creating .venv..." -ForegroundColor Yellow
    python -m venv .venv
    & $VENV_PYTHON -m pip install --upgrade pip
    & $VENV_PYTHON -m pip install -r backend/requirements.txt
}

Write-Host "`n[1/2] Starting Python FastAPI Backend on http://127.0.0.1:8000..." -ForegroundColor Green
$backendProcess = Start-Process -FilePath $VENV_PYTHON -ArgumentList "-m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload" -PassThru

Start-Sleep -Seconds 2

Write-Host "[2/2] Starting Frontend Vite Server on http://localhost:3000..." -ForegroundColor Green
Write-Host "Press Ctrl+C to terminate both servers when finished.`n" -ForegroundColor Yellow

try {
    npm run dev
} finally {
    Write-Host "`nStopping Python Backend..." -ForegroundColor Yellow
    Stop-Process -Id $backendProcess.Id -Force -ErrorAction SilentlyContinue
    Write-Host "VulnSeal servers stopped cleanly." -ForegroundColor Green
}

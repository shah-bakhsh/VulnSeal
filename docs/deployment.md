# 🚀 VulnSeal Production Deployment Guide

VulnSeal can be deployed as an independent full-stack architecture or containerized with Docker.

---

## 1. Architecture Overview
- **Frontend**: Static SPA (built via `vite build` to `/dist`), hosted on Vercel, Netlify, Cloudflare Pages, or Nginx.
- **Backend**: Python FastAPI ASGI server (run via `uvicorn backend.app.main:app`), hosted on Render, Railway, AWS ECS, or a Linux VPS.
- **Database**: PostgreSQL (AWS RDS, Supabase, Railway Postgres) or SQLite for lightweight single-host deployments.

---

## 2. Environment Variables

### Production Backend Environment
```env
APP_ENV=production
PORT=8000
FRONTEND_URL=https://app.vulnseal.com
DATABASE_URL=postgresql://user:password@db-host:5432/vulnseal

# Optional AI Providers (Deterministic AST engine runs automatically if unset)
GEMINI_API_KEY=your_gemini_key
GROQ_API_KEY=your_groq_key
```

### Production Frontend Environment
```env
VITE_BACKEND_URL=https://api.vulnseal.com
```

---

## 3. Docker Deployment
Run both services using `docker compose`:
```bash
docker compose up -d --build
```
This builds and starts:
- Frontend on port `3000`
- Backend API on port `8000`

---

## 4. Linux VPS (Systemd + Nginx)

### Systemd Service (`/etc/systemd/system/vulnseal.service`)
```ini
[Unit]
Description=VulnSeal FastAPI Backend Service
After=network.target

[Service]
User=vulnseal
WorkingDirectory=/opt/vulnseal
ExecStart=/opt/vulnseal/.venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
```

"""
VulnSeal FastAPI Application Server
Autonomous cybersecurity vulnerability scanning, remediation, and verification backend.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .core.config import settings
from .core.logging import logger
from .database.session import init_db
from .database.repository import repo

from .api.health import router as health_router
from .api.targets import router as targets_router
from .api.scans import router as scans_router
from .api.findings import router as findings_router
from .api.remediation import router as remediation_router
from .api.proof import router as proof_router
from .api.activity import router as activity_router
from .api.audit import router as audit_router
from .api.engine import router as engine_router
from .api.demo import router as demo_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing VulnSeal database and state store...")
    init_db()
    repo.seed_initial_data()
    logger.info("VulnSeal backend online and listening.")
    yield
    logger.info("VulnSeal backend shutting down cleanly.")

app = FastAPI(
    title="VulnSeal — Autonomous Security Remediation Platform",
    description="Find. Fix. Prove. Close the cybersecurity remediation loop with deterministic scanning, evidence verification, isolated ShadowFix testing, and cryptographic Proof of Fix.",
    version=settings.APP_VERSION,
    lifespan=lifespan
)

# CORS Middleware (Configured origins and Vercel domains)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if settings.APP_ENV == "development" else [settings.FRONTEND_URL, "https://*.vercel.app"],
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(health_router)
app.include_router(targets_router)
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(remediation_router)
app.include_router(proof_router)
app.include_router(activity_router)
app.include_router(audit_router)
app.include_router(engine_router)
app.include_router(demo_router)

@app.get("/")
def root_endpoint():
    return {
        "status": "online",
        "service": "VulnSeal Autonomous Security Remediation Platform",
        "version": settings.APP_VERSION,
        "tagline": "Find. Fix. Prove.",
        "documentation": "/docs",
        "health": "/api/health",
        "demo_sandbox": "/demo-target"
    }

def run_server(port: int = 8000):
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=port, reload=settings.DEBUG)

if __name__ == "__main__":
    import os
    port = int(os.getenv("PORT", 8000))
    run_server(port)

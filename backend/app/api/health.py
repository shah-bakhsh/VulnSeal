"""
Health Check API
"""
from fastapi import APIRouter
from ..core.config import settings

router = APIRouter(tags=["Health"])

@router.get("/api/health")
def get_health():
    return {
        "status": "ok",
        "service": "vulnseal-api",
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV
    }

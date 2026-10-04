"""
AI Inference & System Status API
"""
from fastapi import APIRouter
from ..ai.model_router import model_router
from ..core.config import settings

router = APIRouter(tags=["Engine Status"])

@router.get("/api/engine/status")
@router.get("/api/ai/status")
def get_engine_status():
    return model_router.get_engine_status()

@router.get("/api/supabase/status")
def get_supabase_status():
    supabase_configured = bool(os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_ANON_KEY"))
    return {
        "connected": False,
        "configured": supabase_configured,
        "url": os.getenv("SUPABASE_URL") or "Not Configured",
        "message": "Local SQLite database active and healthy." if not supabase_configured else "Supabase credentials detected."
    }

import os

"""
Agent Activity & Events API
Provides live streaming timeline and event logs for the 7 VulnSeal specialized agents.
"""
from fastapi import APIRouter, Query
from ..database.repository import repo

router = APIRouter(tags=["Agent Activity"])

@router.get("/api/agent-events")
@router.get("/api/agents/events")
def get_agent_events(workspace_id: str = Query("ws_default_01")):
    return repo.get_agent_events(workspace_id)

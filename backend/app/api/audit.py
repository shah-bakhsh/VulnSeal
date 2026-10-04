"""
Audit Logs API
Provides immutable cryptographic audit trail of all security decisions and human approvals.
"""
from fastapi import APIRouter, Query
from ..database.repository import repo

router = APIRouter(tags=["Audit Logs"])

@router.get("/api/audit-logs")
def get_audit_logs(workspace_id: str = Query("ws_default_01")):
    return repo.get_audit_logs(workspace_id)

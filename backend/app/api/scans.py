"""
Scans API
Initiates scans and retrieves scan progress and history.
"""
from fastapi import APIRouter, HTTPException, Query, Body
from typing import Dict, Any
from ..database.repository import repo
from ..services.scanner import scanner

router = APIRouter(tags=["Scans"])

@router.get("/api/scans")
def get_scans(workspace_id: str = Query("ws_default_01")):
    return repo.get_scans(workspace_id)

@router.post("/api/scans")
def start_scan(body: Dict[str, Any] = Body(...)):
    target_id = body.get("target_id")
    workspace_id = body.get("workspace_id", "ws_default_01")
    if not target_id:
        raise HTTPException(status_code=400, detail="target_id is required.")

    target = repo.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    if target.get("status") != "authorized" and not target.get("is_demo"):
        raise HTTPException(status_code=403, detail="Target is not authorized. Scans cannot proceed without verified ownership.")

    try:
        scan = scanner.execute_scan(target_id, workspace_id)
        return scan
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan

@router.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str):
    scan = repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    repo.update_scan(scan_id, {"status": "cancelled"})
    return repo.get_scan(scan_id)

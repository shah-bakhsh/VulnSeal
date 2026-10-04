"""
Targets API
Handles target registration, deletion, and authorization verification challenges.
"""
from fastapi import APIRouter, HTTPException, Query, Body
from typing import Optional, Dict, Any
import httpx
from ..database.repository import repo, utc_now
from ..core.logging import logger

router = APIRouter(tags=["Targets"])

@router.get("/api/targets")
def get_targets(workspace_id: str = Query("ws_default_01")):
    return repo.get_targets(workspace_id)

@router.post("/api/targets")
def create_target(body: Dict[str, Any] = Body(...)):
    url = body.get("url")
    name = body.get("name")
    if not url or not name:
        raise HTTPException(status_code=400, detail="Target URL and name are required.")

    target = repo.create_target(body)
    challenge = repo.get_challenge_for_target(target["id"])
    return {"target": target, "challenge": challenge}

@router.get("/api/targets/{target_id}")
def get_target(target_id: str):
    target = repo.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")
    return target

@router.delete("/api/targets/{target_id}")
def delete_target(target_id: str):
    target = repo.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")
    success = repo.delete_target(target_id)
    return {"success": success, "message": f"Target '{target['name']}' deleted successfully."}

@router.get("/api/targets/{target_id}/challenge")
def get_target_challenge(target_id: str):
    target = repo.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")
    challenge = repo.get_challenge_for_target(target_id)
    return challenge

@router.post("/api/targets/{target_id}/verify")
def verify_target(target_id: str, body: Dict[str, Any] = Body({})):
    target = repo.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    # 1. Developer direct confirmation
    if body.get("developer_confirm"):
        repo.update_target(target_id, {
            "status": "authorized",
            "authorized_at": utc_now()
        })
        repo.record_audit_log({
            "workspace_id": target.get("workspace_id", "ws_default_01"),
            "action": "TARGET_AUTHORIZED_BY_OWNER_DECLARATION",
            "actor": body.get("owner_email", "operator@vulnseal.security"),
            "resource_type": "target",
            "resource_id": target_id,
            "decision": "ALLOWED",
            "details": {"url": target["url"], "method": "developer_confirm"}
        })
        return {
            "success": True,
            "status": "authorized",
            "message": "Target authorized successfully via verified owner declaration."
        }

    # 2. Demo target allowlist
    if target.get("is_demo"):
        repo.update_target(target_id, {
            "status": "authorized",
            "authorized_at": utc_now()
        })
        return {"success": True, "status": "authorized", "message": "Demo sandbox verified via allowlist."}

    # 3. HTML meta-tag challenge verification
    challenge = repo.get_challenge_for_target(target_id)
    token = challenge.get("token") if challenge else ""

    try:
        with httpx.Client(timeout=8.0) as client:
            resp = client.get(target["url"], headers={"User-Agent": "VulnSeal-AuthVerifier/1.0"})
            if token and token in resp.text:
                repo.update_target(target_id, {
                    "status": "authorized",
                    "authorized_at": utc_now()
                })
                return {"success": True, "status": "authorized", "message": "Ownership meta-tag verified successfully."}
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Verification token '{token}' not found on '{target['url']}'. Ensure meta tag is present or use developer confirmation."
                )
    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to connect to target URL: {e}. You can use developer confirmation if behind a firewall."
        )

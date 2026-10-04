"""
Demo Lab & Sandbox Endpoints API
Controls Demo Lab reset and mounts the intentionally vulnerable Apex Commercial Banking target.
"""
from fastapi import APIRouter, Request, Response, Body
from fastapi.responses import HTMLResponse
from typing import Dict, Any
from ..demo.target import demo_sandbox
from ..database.repository import repo

router = APIRouter(tags=["Demo Lab"])

@router.get("/api/workspaces")
def get_workspaces():
    return repo.get_workspaces()

@router.post("/api/demo/reset")
def reset_demo(body: Dict[str, Any] = Body({})):
    workspace_id = body.get("workspace_id", "ws_default_01")
    demo_sandbox.reset_state()
    repo.reset_demo_state(workspace_id)
    return {
        "success": True,
        "message": "Demo target restored to fresh vulnerable baseline."
    }

@router.get("/demo-target", response_class=HTMLResponse)
def get_demo_target_ui():
    return demo_sandbox.get_index_html()

@router.post("/demo-target/login")
def demo_target_login(request: Request, response: Response):
    res = demo_sandbox.handle_request("/demo-target/login", "POST", dict(request.headers))
    for k, v in res.get("headers", {}).items():
        response.headers[k] = v
    response.status_code = res.get("status", 200)
    return Response(content=res.get("body", ""), media_type="application/json", headers=dict(response.headers))

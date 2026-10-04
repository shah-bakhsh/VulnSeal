"""
SecurityInspector Agent (Agent 3)
Executes deterministic security inspection rules across mapped target surfaces.
"""
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin
from ..security.network_guard import NetworkGuard
from ..security.rules.cookie_rule import CookieSecurityRule
from ..security.rules.cors_rule import CorsSecurityRule
from ..security.rules.headers_rule import HeadersSecurityRule
from ..database.repository import repo

class SecurityInspectorAgent:
    NAME = "SecurityInspector"

    @classmethod
    def inspect(cls, target_url: str, surface: Dict[str, Any], is_demo: bool = False, workspace_id: str = "ws_default_01", scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        cls._log_event(workspace_id, scan_id, "start", "in_progress", "Executing deterministic inspection engines across target surfaces...")

        candidate_findings = []
        headers = surface.get("headers", {})
        body = surface.get("body", "")
        status_code = surface.get("status_code", 200)

        # 1. Inspect defensive headers
        candidate_findings.extend(HeadersSecurityRule.execute(target_url, headers, body, status_code))

        # 2. Inspect CORS configuration
        candidate_findings.extend(CorsSecurityRule.execute(target_url, headers, body, status_code))

        # 3. Inspect cookies on root
        candidate_findings.extend(CookieSecurityRule.execute(target_url, headers, body, status_code))

        # 4. Probe authentication endpoints (e.g. login) if present in surface
        endpoints = surface.get("endpoints", [])
        for ep in endpoints:
            if "login" in ep.lower() or "auth" in ep.lower():
                try:
                    login_resp = NetworkGuard.execute_guarded_request("POST", ep, is_demo=is_demo, data={"username": "demo", "password": "password"})
                    candidate_findings.extend(
                        CookieSecurityRule.execute(ep, dict(login_resp.headers), login_resp.text, login_resp.status_code)
                    )
                except Exception:
                    # In local demo fallback, inspect simulated cookie
                    if is_demo:
                        sim_headers = {"Set-Cookie": "session_id=vuln_session_token_xyz987; Path=/"}
                        candidate_findings.extend(CookieSecurityRule.execute(ep, sim_headers, "{}", 200))

        cls._log_event(
            workspace_id,
            scan_id,
            "observe",
            "success",
            f"Rule evaluation completed: {len(candidate_findings)} candidate findings identified.",
            metadata={"candidate_count": len(candidate_findings)}
        )

        return candidate_findings

    @classmethod
    def _log_event(cls, workspace_id: str, scan_id: Optional[str], event_type: str, status: str, message: str, metadata: Optional[Dict[str, Any]] = None):
        repo.record_agent_event({
            "workspace_id": workspace_id,
            "scan_id": scan_id,
            "agent": cls.NAME,
            "event_type": event_type,
            "status": status,
            "message": message,
            "metadata": metadata or {}
        })

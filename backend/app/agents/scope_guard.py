"""
ScopeGuard Agent (Agent 1)
Enforces origin authorization and blocks SSRF, private network abuse, and unverified targets.
"""
from typing import Tuple, Dict, Any, Optional
from ..security.network_guard import NetworkGuard
from ..database.repository import repo

class ScopeGuardAgent:
    NAME = "ScopeGuard"

    @classmethod
    def evaluate(cls, target: Dict[str, Any], workspace_id: str = "ws_default_01", scan_id: Optional[str] = None) -> Tuple[bool, str]:
        target_url = target.get("url", "")
        is_demo = bool(target.get("is_demo", False))
        status = target.get("status", "unverified")

        # 1. Authorization check
        if status != "authorized" and not is_demo:
            msg = f"Target '{target_url}' is not authorized. Scans cannot proceed without verified ownership challenge."
            cls._log_event(workspace_id, scan_id, "block", "error", msg)
            repo.record_audit_log({
                "workspace_id": workspace_id,
                "action": "TARGET_UNAUTHORIZED_BLOCKED",
                "actor": cls.NAME,
                "resource_type": "target",
                "resource_id": target.get("id"),
                "decision": "DENIED",
                "details": {"reason": msg}
            })
            return False, msg

        # 2. Network safety and SSRF check via NetworkGuard
        allowed, reason, rule_id = NetworkGuard.evaluate_target_url(target_url, is_demo=is_demo)
        if not allowed:
            msg = f"ScopeGuard blocked '{target_url}': {reason} (Rule: {rule_id})"
            cls._log_event(workspace_id, scan_id, "block", "error", msg)
            repo.record_audit_log({
                "workspace_id": workspace_id,
                "action": "SCAN_BLOCKED_SSRF",
                "actor": cls.NAME,
                "resource_type": "target",
                "resource_id": target.get("id"),
                "decision": "DENIED",
                "details": {"reason": reason, "rule_id": rule_id}
            })
            return False, msg

        cls._log_event(workspace_id, scan_id, "decision", "success", f"Target verified within ScopeGuard authorization envelope: {reason}")
        return True, reason

    @classmethod
    def _log_event(cls, workspace_id: str, scan_id: Optional[str], event_type: str, status: str, message: str):
        repo.record_agent_event({
            "workspace_id": workspace_id,
            "scan_id": scan_id,
            "agent": cls.NAME,
            "event_type": event_type,
            "status": status,
            "message": message
        })

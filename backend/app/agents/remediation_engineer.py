"""
RemediationEngineer Agent (Agent 6)
Synthesizes minimal, safe unified diff patches and automated regression test assertions.
"""
from typing import Dict, Any, Optional
from ..ai.model_router import model_router
from ..database.repository import repo

class RemediationEngineerAgent:
    NAME = "RemediationEngineer"

    @classmethod
    def synthesize_patch(cls, finding: Dict[str, Any], root_cause: Dict[str, Any], workspace_id: str = "ws_default_01") -> Dict[str, Any]:
        finding_id = finding.get("id")
        cls._log_event(
            workspace_id,
            finding_id,
            "start",
            "in_progress",
            "RemediationEngineer generating minimal safe patch candidate and regression assertions..."
        )

        analysis = model_router.analyze_vulnerability(finding)
        patch = analysis.get("patch", {})

        cls._log_event(
            workspace_id,
            finding_id,
            "complete",
            "success",
            f"Synthesized minimal patch candidate (SHA-256: {patch.get('sha256_hash', '')[:10]}...). Human approval required.",
            metadata={"patch_hash": patch.get("sha256_hash"), "affected_file": patch.get("affected_file")}
        )

        return patch

    @classmethod
    def _log_event(cls, workspace_id: str, finding_id: Optional[str], event_type: str, status: str, message: str, metadata: Optional[Dict[str, Any]] = None):
        repo.record_agent_event({
            "workspace_id": workspace_id,
            "finding_id": finding_id,
            "agent": cls.NAME,
            "event_type": event_type,
            "status": status,
            "message": message,
            "metadata": metadata or {}
        })

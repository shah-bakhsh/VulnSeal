"""
RootCauseMapper Agent (Agent 5)
Pinpoints the exact source code file, line number, and AST symbol establishing the vulnerability.
"""
from typing import Dict, Any, Optional
from ..ai.model_router import model_router
from ..database.repository import repo

class RootCauseMapperAgent:
    NAME = "RootCauseMapper"

    @classmethod
    def map_root_cause(cls, finding: Dict[str, Any], workspace_id: str = "ws_default_01") -> Dict[str, Any]:
        finding_id = finding.get("id")
        cls._log_event(
            workspace_id,
            finding_id,
            "start",
            "in_progress",
            f"RootCauseMapper analyzing source code for finding '{finding.get('title')}'..."
        )

        analysis = model_router.analyze_vulnerability(finding)
        root_cause = analysis.get("rootCause", {})

        cls._log_event(
            workspace_id,
            finding_id,
            "complete",
            "success",
            f"Root cause identified: {root_cause.get('file_path')}:{root_cause.get('line_number')} ({root_cause.get('symbol')})",
            metadata=root_cause
        )

        return root_cause

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

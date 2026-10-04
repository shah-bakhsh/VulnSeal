"""
VulnSeal Autonomous Scanner Orchestrator (Python)
Coordinates ScopeGuard, SurfaceMapper, SecurityInspector, and EvidenceJudge in sequence.
"""
import time
from typing import Dict, Any
from ..database.repository import repo, utc_now
from ..agents.scope_guard import ScopeGuardAgent
from ..agents.surface_mapper import SurfaceMapperAgent
from ..agents.security_inspector import SecurityInspectorAgent
from ..agents.evidence_judge import EvidenceJudgeAgent

class ScannerOrchestrator:
    @classmethod
    def execute_scan(cls, target_id: str, workspace_id: str = "ws_default_01") -> Dict[str, Any]:
        target = repo.get_target(target_id)
        if not target:
            raise ValueError(f"Target '{target_id}' not found.")

        target_url = target["url"]
        is_demo = bool(target.get("is_demo", False))

        scan = repo.create_scan(target_id, target_url, workspace_id)
        scan_id = scan["id"]
        start_time = time.time()

        # Step 1: ScopeGuard Check
        repo.update_scan(scan_id, {"status": "authorizing"})
        is_authorized, reason = ScopeGuardAgent.evaluate(target, workspace_id, scan_id)
        if not is_authorized:
            repo.update_scan(scan_id, {"status": "blocked", "error_message": reason})
            return repo.get_scan(scan_id)

        # Step 2: SurfaceMapper Crawl
        repo.update_scan(scan_id, {"status": "discovering"})
        surface = SurfaceMapperAgent.map_surface(target_url, is_demo=is_demo, workspace_id=workspace_id, scan_id=scan_id)

        # Step 3: SecurityInspector Rule Evaluation
        repo.update_scan(scan_id, {"status": "scanning"})
        candidates = SecurityInspectorAgent.inspect(target_url, surface, is_demo=is_demo, workspace_id=workspace_id, scan_id=scan_id)

        # Step 4: EvidenceJudge Triage & False-Positive Elimination
        repo.update_scan(scan_id, {"status": "triaging"})
        confirmed_findings = EvidenceJudgeAgent.judge_and_commit(candidates, target_id, scan_id, workspace_id)

        duration_ms = int((time.time() - start_time) * 1000)
        confirmed_count = len(confirmed_findings)

        # Step 5: Finalize Scan Record
        repo.update_scan(scan_id, {
            "status": "completed",
            "pages_discovered": len(surface.get("endpoints", [])),
            "rules_executed": 3,
            "candidate_findings_count": len(candidates),
            "confirmed_findings_count": confirmed_count,
            "requests_made": len(surface.get("endpoints", [])) + 2,
            "completed_at": utc_now(),
            "duration_ms": duration_ms
        })

        # Update Target Security Score and Finding Count (One Source of Truth)
        security_score = max(20, 100 - (confirmed_count * 15))
        repo.update_target(target_id, {
            "security_score": security_score,
            "open_findings_count": confirmed_count,
            "last_scan_at": utc_now()
        })

        return repo.get_scan(scan_id)

scanner = ScannerOrchestrator()

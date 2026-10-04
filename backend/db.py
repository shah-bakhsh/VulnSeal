"""
VulnSeal Database & State Repository (Python)
In-memory and persistent PostgreSQL state management for targets, scans, findings, proofs, and audit logs.
"""
import uuid
import datetime
from typing import Dict, List, Any, Optional

class Database:
    def __init__(self):
        self.workspaces: Dict[str, Dict[str, Any]] = {
            "ws_default_01": {
                "id": "ws_default_01",
                "name": "VulnSeal Primary Workspace",
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
        }
        self.targets: Dict[str, Dict[str, Any]] = {}
        self.scans: Dict[str, Dict[str, Any]] = {}
        self.findings: Dict[str, Dict[str, Any]] = {}
        self.proofs: Dict[str, Dict[str, Any]] = {}
        self.agent_events: List[Dict[str, Any]] = []
        self.audit_logs: List[Dict[str, Any]] = []
        self.challenges: Dict[str, Dict[str, Any]] = {}

        self._seed_default_targets()

    def _seed_default_targets(self):
        demo_id = "target_demo_sandbox"
        self.targets[demo_id] = {
            "id": demo_id,
            "workspace_id": "ws_default_01",
            "url": "http://localhost:3000/demo-target",
            "name": "Intentionally Vulnerable Banking Lab",
            "is_demo": True,
            "status": "authorized",
            "security_score": 42,
            "open_findings_count": 4,
            "verified_fixes_count": 0,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "authorized_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }

    # Workspaces
    def get_workspaces(self) -> List[Dict[str, Any]]:
        return list(self.workspaces.values())

    # Targets
    def get_targets(self, workspace_id: str = "ws_default_01") -> List[Dict[str, Any]]:
        return [t for t in self.targets.values() if t.get("workspace_id") == workspace_id]

    def get_target_by_id(self, target_id: str) -> Optional[Dict[str, Any]]:
        return self.targets.get(target_id)

    def create_target(self, data: Dict[str, Any]) -> Dict[str, Any]:
        target_id = f"tgt_{uuid.uuid4().hex[:8]}"
        target = {
            "id": target_id,
            "workspace_id": data.get("workspace_id", "ws_default_01"),
            "url": data["url"],
            "name": data["name"],
            "is_demo": bool(data.get("is_demo", False)),
            "status": "authorized" if data.get("is_demo") else "unverified",
            "security_score": None,
            "open_findings_count": 0,
            "verified_fixes_count": 0,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self.targets[target_id] = target
        return target

    # Scans
    def get_scans(self, workspace_id: str = "ws_default_01") -> List[Dict[str, Any]]:
        return [s for s in self.scans.values() if s.get("workspace_id") == workspace_id]

    def get_scan_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return self.scans.get(scan_id)

    def create_scan(self, target_id: str, target_url: str, workspace_id: str = "ws_default_01") -> Dict[str, Any]:
        scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        scan = {
            "id": scan_id,
            "workspace_id": workspace_id,
            "target_id": target_id,
            "target_url": target_url,
            "status": "queued",
            "pages_discovered": 0,
            "rules_executed": 0,
            "candidate_findings_count": 0,
            "confirmed_findings_count": 0,
            "dismissed_findings_count": 0,
            "requests_made": 0,
            "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        self.scans[scan_id] = scan
        return scan

    def update_scan(self, scan_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        scan = self.scans.get(scan_id)
        if scan:
            scan.update(updates)
        return scan

    # Findings
    def get_findings(self, workspace_id: str = "ws_default_01") -> List[Dict[str, Any]]:
        return [f for f in self.findings.values() if f.get("workspace_id") == workspace_id]

    def get_finding_by_id(self, finding_id: str) -> Optional[Dict[str, Any]]:
        return self.findings.get(finding_id)

    def create_finding(self, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        fid = finding_data.get("id") or f"fnd_{uuid.uuid4().hex[:8]}"
        finding_data["id"] = fid
        finding_data["created_at"] = finding_data.get("created_at") or datetime.datetime.now(datetime.timezone.utc).isoformat()
        finding_data["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.findings[fid] = finding_data
        return finding_data

    def update_finding(self, finding_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        f = self.findings.get(finding_id)
        if f:
            f.update(updates)
            f["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return f

    # Proofs
    def get_proofs(self, workspace_id: str = "ws_default_01") -> List[Dict[str, Any]]:
        return [p for p in self.proofs.values() if p.get("workspace_id") == workspace_id]

    def create_proof(self, proof_data: Dict[str, Any]) -> Dict[str, Any]:
        pid = proof_data.get("id") or f"proof_{uuid.uuid4().hex[:8]}"
        proof_data["id"] = pid
        self.proofs[pid] = proof_data
        return proof_data

    # Agent Events & Audit Logs
    def record_agent_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        event["id"] = event.get("id") or f"evt_{uuid.uuid4().hex[:8]}"
        event["created_at"] = event.get("created_at") or datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.agent_events.insert(0, event)
        return event

    def get_agent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.agent_events[:limit]

    def record_audit_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        log["id"] = log.get("id") or f"aud_{uuid.uuid4().hex[:8]}"
        log["timestamp"] = log.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.audit_logs.insert(0, log)
        return log

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.audit_logs[:limit]

db = Database()

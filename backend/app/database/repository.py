"""
VulnSeal Database Repository
Thread-safe CRUD operations and model serialization for SQLite and PostgreSQL.
"""
import json
import uuid
import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from .session import SessionLocal
from .models import (
    WorkspaceModel,
    TargetModel,
    ChallengeModel,
    ScanModel,
    FindingModel,
    PatchModel,
    ApprovalModel,
    ProofModel,
    AgentEventModel,
    AuditLogModel,
    utc_now
)

def _loads(val: Optional[str], default=None):
    if not val:
        return default if default is not None else {}
    try:
        return json.loads(val)
    except Exception:
        return default if default is not None else {}

def _dumps(val: Any) -> str:
    if val is None:
        return "{}"
    if isinstance(val, str):
        return val
    return json.dumps(val)

class Repository:
    def __init__(self):
        pass

    def seed_initial_data(self):
        with SessionLocal() as db:
            # 1. Ensure Default Workspace exists
            ws = db.query(WorkspaceModel).filter(WorkspaceModel.id == "ws_default_01").first()
            if not ws:
                ws = WorkspaceModel(
                    id="ws_default_01",
                    name="VulnSeal Primary Workspace",
                    created_at=utc_now()
                )
                db.add(ws)

            # 2. Ensure Demo Sandbox Target exists (with score=None and findings=0 until scanned)
            demo_target = db.query(TargetModel).filter(TargetModel.id == "target_demo_sandbox").first()
            if not demo_target:
                demo_target = TargetModel(
                    id="target_demo_sandbox",
                    workspace_id="ws_default_01",
                    url="http://localhost:3000/demo-target",
                    name="Apex Global Commercial Banking (Demo Lab)",
                    is_demo=True,
                    status="authorized",
                    security_score=None,  # Not assessed until first real scan
                    open_findings_count=0,
                    verified_fixes_count=0,
                    authorized_at=utc_now(),
                    created_at=utc_now()
                )
                db.add(demo_target)

                # Seed challenge
                chal = ChallengeModel(
                    id="chal_demo_01",
                    target_id="target_demo_sandbox",
                    challenge_type="demo_allowlist",
                    token="vs-demo-authorized-sandbox-token",
                    status="verified",
                    created_at=utc_now(),
                    verified_at=utc_now()
                )
                db.add(chal)

            db.commit()

    # --- Workspaces ---
    def get_workspaces(self) -> List[Dict[str, Any]]:
        with SessionLocal() as db:
            rows = db.query(WorkspaceModel).all()
            return [{"id": r.id, "name": r.name, "created_at": r.created_at} for r in rows]

    # --- Targets ---
    def get_targets(self, workspace_id: str = "ws_default_01") -> List[Dict[str, Any]]:
        with SessionLocal() as db:
            rows = db.query(TargetModel).filter(TargetModel.workspace_id == workspace_id).all()
            return [self._target_to_dict(r) for r in rows]

    def get_target(self, target_id: str) -> Optional[Dict[str, Any]]:
        with SessionLocal() as db:
            r = db.query(TargetModel).filter(TargetModel.id == target_id).first()
            return self._target_to_dict(r) if r else None

    def create_target(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with SessionLocal() as db:
            is_demo = bool(data.get("is_demo", False))
            target = TargetModel(
                workspace_id=data.get("workspace_id", "ws_default_01"),
                url=data["url"],
                name=data["name"],
                is_demo=is_demo,
                status="authorized" if is_demo else "unverified",
                authorized_at=utc_now() if is_demo else None,
                security_score=None,
                open_findings_count=0,
                verified_fixes_count=0
            )
            db.add(target)
            db.flush()

            # Create verification challenge
            token = f"vulnseal-verify-{uuid.uuid4().hex[:16]}"
            chal = ChallengeModel(
                target_id=target.id,
                challenge_type="demo_allowlist" if is_demo else "meta_tag",
                token=token,
                status="verified" if is_demo else "pending"
            )
            db.add(chal)
            db.commit()
            db.refresh(target)
            return self._target_to_dict(target)

    def update_target(self, target_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with SessionLocal() as db:
            r = db.query(TargetModel).filter(TargetModel.id == target_id).first()
            if not r:
                return None
            for k, v in updates.items():
                if hasattr(r, k):
                    setattr(r, k, v)
            db.commit()
            db.refresh(r)
            return self._target_to_dict(r)

    def delete_target(self, target_id: str) -> bool:
        with SessionLocal() as db:
            r = db.query(TargetModel).filter(TargetModel.id == target_id).first()
            if not r:
                return False
            db.delete(r)
            db.commit()
            return True

    def get_challenge_for_target(self, target_id: str) -> Optional[Dict[str, Any]]:
        with SessionLocal() as db:
            c = db.query(ChallengeModel).filter(ChallengeModel.target_id == target_id).first()
            if not c:
                token = f"vulnseal-verify-{uuid.uuid4().hex[:16]}"
                c = ChallengeModel(
                    target_id=target_id,
                    challenge_type="meta_tag",
                    token=token,
                    status="pending"
                )
                db.add(c)
                db.commit()
                db.refresh(c)
            return {
                "id": c.id,
                "target_id": c.target_id,
                "type": c.challenge_type,
                "token": c.token,
                "status": c.status,
                "created_at": c.created_at,
                "verified_at": c.verified_at
            }

    # --- Scans ---
    def get_scans(self, workspace_id: str = "ws_default_01") -> List[Dict[str, Any]]:
        with SessionLocal() as db:
            rows = db.query(ScanModel).filter(ScanModel.workspace_id == workspace_id).order_by(ScanModel.started_at.desc()).all()
            return [self._scan_to_dict(r) for r in rows]

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with SessionLocal() as db:
            r = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            return self._scan_to_dict(r) if r else None

    def create_scan(self, target_id: str, target_url: str, workspace_id: str = "ws_default_01") -> Dict[str, Any]:
        with SessionLocal() as db:
            scan = ScanModel(
                workspace_id=workspace_id,
                target_id=target_id,
                target_url=target_url,
                status="queued",
                scope_json=json.dumps({
                    "target_id": target_id,
                    "allowed_origin": target_url,
                    "allowed_paths": ["/"],
                    "excluded_paths": ["/logout"],
                    "max_pages": 15,
                    "request_budget": 30,
                    "rate_limit_per_second": 5,
                    "active_testing_permitted": True
                })
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            return self._scan_to_dict(scan)

    def update_scan(self, scan_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with SessionLocal() as db:
            r = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            if not r:
                return None
            for k, v in updates.items():
                if k == "scope":
                    r.scope_json = _dumps(v)
                elif hasattr(r, k):
                    setattr(r, k, v)
            db.commit()
            db.refresh(r)
            return self._scan_to_dict(r)

    # --- Findings ---
    def get_findings(self, workspace_id: str = "ws_default_01") -> List[Dict[str, Any]]:
        with SessionLocal() as db:
            rows = db.query(FindingModel).filter(FindingModel.workspace_id == workspace_id).order_by(FindingModel.created_at.desc()).all()
            return [self._finding_to_dict(r) for r in rows]

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        with SessionLocal() as db:
            r = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
            return self._finding_to_dict(r) if r else None

    def create_finding(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with SessionLocal() as db:
            finding = FindingModel(
                id=data.get("id") or f"fnd_{uuid.uuid4().hex[:10]}",
                workspace_id=data.get("workspace_id", "ws_default_01"),
                target_id=data["target_id"],
                scan_id=data["scan_id"],
                rule_id=data["rule_id"],
                rule_name=data["rule_name"],
                category=data.get("category", "Security"),
                title=data["title"],
                description=data["description"],
                affected_url=data["affected_url"],
                severity=data.get("severity", "medium"),
                confidence=float(data.get("confidence", 1.0)),
                status=data.get("status", "confirmed"),
                evidence_json=_dumps(data.get("evidence", {})),
                root_cause_json=_dumps(data.get("rootCause")) if data.get("rootCause") else None,
                patch_json=_dumps(data.get("patch")) if data.get("patch") else None,
                approval_json=_dumps(data.get("approval")) if data.get("approval") else None,
                proof_id=data.get("proof_id")
            )
            db.add(finding)
            db.commit()
            db.refresh(finding)
            return self._finding_to_dict(finding)

    def update_finding(self, finding_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        with SessionLocal() as db:
            r = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
            if not r:
                return None
            for k, v in updates.items():
                if k == "evidence":
                    r.evidence_json = _dumps(v)
                elif k in ("rootCause", "root_cause"):
                    r.root_cause_json = _dumps(v)
                elif k == "patch":
                    r.patch_json = _dumps(v)
                elif k == "approval":
                    r.approval_json = _dumps(v)
                elif hasattr(r, k):
                    setattr(r, k, v)
            r.updated_at = utc_now()
            db.commit()
            db.refresh(r)
            return self._finding_to_dict(r)

    # --- Patches & Approvals ---
    def get_patch_for_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        with SessionLocal() as db:
            f = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
            if f and f.patch_json:
                return _loads(f.patch_json)
            p = db.query(PatchModel).filter(PatchModel.finding_id == finding_id).first()
            return self._patch_to_dict(p) if p else None

    def create_patch(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        with SessionLocal() as db:
            patch_id = patch.get("id") or f"patch_{uuid.uuid4().hex[:10]}"
            existing = db.query(PatchModel).filter(PatchModel.id == patch_id).first()
            if existing:
                existing.finding_id = patch["finding_id"]
                existing.affected_file = patch.get("affected_file", "")
                existing.diff = patch.get("diff", "")
                existing.sha256_hash = patch.get("sha256_hash", "")
                existing.explanation = patch.get("explanation", "")
                existing.security_effect = patch.get("security_effect", "")
                existing.risk_assessment = patch.get("risk_assessment", "")
                existing.generated_regression_test = patch.get("generated_regression_test", "")
                existing.verification_plan = patch.get("verification_plan", "")
                db.commit()
                return patch

            p = PatchModel(
                id=patch_id,
                finding_id=patch["finding_id"],
                affected_file=patch.get("affected_file", ""),
                diff=patch.get("diff", ""),
                sha256_hash=patch.get("sha256_hash", ""),
                explanation=patch.get("explanation", ""),
                security_effect=patch.get("security_effect", ""),
                risk_assessment=patch.get("risk_assessment", ""),
                generated_regression_test=patch.get("generated_regression_test", ""),
                verification_plan=patch.get("verification_plan", "")
            )
            db.add(p)
            db.commit()
            return patch

    def create_approval(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with SessionLocal() as db:
            appr = ApprovalModel(
                patch_id=data["patch_id"],
                approved_by_email=data.get("approved_by_email", "operator@vulnseal.security"),
                approved_patch_hash=data["approved_patch_hash"],
                status=data.get("status", "approved"),
                rejection_reason=data.get("rejection_reason")
            )
            db.add(appr)
            db.commit()
            return {
                "id": appr.id,
                "patch_id": appr.patch_id,
                "approved_by_email": appr.approved_by_email,
                "approved_patch_hash": appr.approved_patch_hash,
                "status": appr.status,
                "rejection_reason": appr.rejection_reason,
                "approved_at": appr.approved_at
            }

    # --- Proofs ---
    def get_proofs(self, workspace_id: str = "ws_default_01") -> List[Dict[str, Any]]:
        with SessionLocal() as db:
            rows = db.query(ProofModel).filter(ProofModel.workspace_id == workspace_id).order_by(ProofModel.verified_at.desc()).all()
            return [self._proof_to_dict(r) for r in rows]

    def get_proof(self, proof_id: str) -> Optional[Dict[str, Any]]:
        with SessionLocal() as db:
            r = db.query(ProofModel).filter(ProofModel.id == proof_id).first()
            return self._proof_to_dict(r) if r else None

    def create_proof(self, proof: Dict[str, Any]) -> Dict[str, Any]:
        with SessionLocal() as db:
            proof_id = proof.get("id") or f"proof_{uuid.uuid4().hex[:10]}"
            existing = db.query(ProofModel).filter(ProofModel.id == proof_id).first()
            if existing:
                return proof

            p = ProofModel(
                id=proof_id,
                workspace_id=proof.get("workspace_id", "ws_default_01"),
                finding_id=proof["finding_id"],
                target_url=proof.get("target_url", ""),
                rule_id=proof.get("rule_id", ""),
                rule_title=proof.get("rule_title", ""),
                severity=proof.get("severity", "medium"),
                root_cause_file=proof.get("root_cause_file", ""),
                root_cause_line=proof.get("root_cause_line", 1),
                patch_diff=proof.get("patch_diff", ""),
                patch_hash=proof.get("patch_hash", ""),
                approved_by=proof.get("approved_by", ""),
                approved_at=proof.get("approved_at", utc_now()),
                before_evidence_json=_dumps(proof.get("before_evidence", {})),
                after_evidence_json=_dumps(proof.get("after_evidence", {})),
                security_replay_status=proof.get("security_replay_status", "PASS"),
                regression_test_status=proof.get("regression_test_status", "PASS"),
                verifier_verdict=proof.get("verifier_verdict", "VERIFIED"),
                verified_at=proof.get("verified_at", utc_now()),
                proof_hash=proof.get("proof_hash", "")
            )
            db.add(p)
            db.commit()
            return proof

    # --- Agent Events & Audit Logs ---
    def get_agent_events(self, workspace_id: str = "ws_default_01") -> List[Dict[str, Any]]:
        with SessionLocal() as db:
            rows = db.query(AgentEventModel).filter(AgentEventModel.workspace_id == workspace_id).order_by(AgentEventModel.created_at.desc()).limit(100).all()
            return [{
                "id": r.id,
                "workspace_id": r.workspace_id,
                "scan_id": r.scan_id,
                "finding_id": r.finding_id,
                "agent": r.agent,
                "event_type": r.event_type,
                "status": r.status,
                "message": r.message,
                "metadata": _loads(r.metadata_json),
                "created_at": r.created_at,
                "duration_ms": r.duration_ms
            } for r in rows]

    def record_agent_event(self, event: Dict[str, Any]):
        with SessionLocal() as db:
            evt = AgentEventModel(
                workspace_id=event.get("workspace_id", "ws_default_01"),
                scan_id=event.get("scan_id"),
                finding_id=event.get("finding_id"),
                agent=event["agent"],
                event_type=event.get("event_type", "start"),
                status=event.get("status", "in_progress"),
                message=event["message"],
                metadata_json=_dumps(event.get("metadata", {})),
                duration_ms=event.get("duration_ms")
            )
            db.add(evt)
            db.commit()

    def get_audit_logs(self, workspace_id: str = "ws_default_01") -> List[Dict[str, Any]]:
        with SessionLocal() as db:
            rows = db.query(AuditLogModel).filter(AuditLogModel.workspace_id == workspace_id).order_by(AuditLogModel.timestamp.desc()).limit(100).all()
            return [{
                "id": r.id,
                "workspace_id": r.workspace_id,
                "action": r.action,
                "actor": r.actor,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "decision": r.decision,
                "details": _loads(r.details_json),
                "timestamp": r.timestamp
            } for r in rows]

    def record_audit_log(self, log: Dict[str, Any]):
        with SessionLocal() as db:
            al = AuditLogModel(
                workspace_id=log.get("workspace_id", "ws_default_01"),
                action=log["action"],
                actor=log["actor"],
                resource_type=log["resource_type"],
                resource_id=log["resource_id"],
                decision=log.get("decision"),
                details_json=_dumps(log.get("details", {}))
            )
            db.add(al)
            db.commit()

    def reset_demo_state(self, workspace_id: str = "ws_default_01"):
        with SessionLocal() as db:
            # Clear demo findings, scans, proofs
            db.query(FindingModel).filter(FindingModel.target_id == "target_demo_sandbox").delete()
            db.query(ScanModel).filter(ScanModel.target_id == "target_demo_sandbox").delete()
            db.query(ProofModel).filter(ProofModel.target_url.contains("demo-target")).delete()
            demo_target = db.query(TargetModel).filter(TargetModel.id == "target_demo_sandbox").first()
            if demo_target:
                demo_target.security_score = None
                demo_target.open_findings_count = 0
                demo_target.verified_fixes_count = 0
                demo_target.last_scan_at = None
            db.commit()

    # --- Serialization Helpers ---
    def _target_to_dict(self, t: TargetModel) -> Dict[str, Any]:
        return {
            "id": t.id,
            "workspace_id": t.workspace_id,
            "url": t.url,
            "name": t.name,
            "is_demo": t.is_demo,
            "status": t.status,
            "authorized_at": t.authorized_at,
            "last_scan_at": t.last_scan_at,
            "security_score": t.security_score,
            "open_findings_count": t.open_findings_count,
            "verified_fixes_count": t.verified_fixes_count,
            "created_at": t.created_at
        }

    def _scan_to_dict(self, s: ScanModel) -> Dict[str, Any]:
        return {
            "id": s.id,
            "workspace_id": s.workspace_id,
            "target_id": s.target_id,
            "target_url": s.target_url,
            "status": s.status,
            "pages_discovered": s.pages_discovered,
            "rules_executed": s.rules_executed,
            "candidate_findings_count": s.candidate_findings_count,
            "confirmed_findings_count": s.confirmed_findings_count,
            "dismissed_findings_count": s.dismissed_findings_count,
            "requests_made": s.requests_made,
            "started_at": s.started_at,
            "completed_at": s.completed_at,
            "duration_ms": s.duration_ms,
            "error_message": s.error_message,
            "scope": _loads(s.scope_json)
        }

    def _finding_to_dict(self, f: FindingModel) -> Dict[str, Any]:
        res = {
            "id": f.id,
            "workspace_id": f.workspace_id,
            "target_id": f.target_id,
            "scan_id": f.scan_id,
            "rule_id": f.rule_id,
            "rule_name": f.rule_name,
            "category": f.category,
            "title": f.title,
            "description": f.description,
            "affected_url": f.affected_url,
            "severity": f.severity,
            "confidence": f.confidence,
            "status": f.status,
            "evidence": _loads(f.evidence_json),
            "created_at": f.created_at,
            "updated_at": f.updated_at
        }
        if f.root_cause_json:
            res["rootCause"] = _loads(f.root_cause_json)
        if f.patch_json:
            res["patch"] = _loads(f.patch_json)
        if f.approval_json:
            res["approval"] = _loads(f.approval_json)
        if f.proof_id:
            res["proof_id"] = f.proof_id
        return res

    def _patch_to_dict(self, p: PatchModel) -> Dict[str, Any]:
        return {
            "id": p.id,
            "finding_id": p.finding_id,
            "affected_file": p.affected_file,
            "diff": p.diff,
            "sha256_hash": p.sha256_hash,
            "explanation": p.explanation,
            "security_effect": p.security_effect,
            "risk_assessment": p.risk_assessment,
            "generated_regression_test": p.generated_regression_test,
            "verification_plan": p.verification_plan,
            "created_at": p.created_at
        }

    def _proof_to_dict(self, p: ProofModel) -> Dict[str, Any]:
        return {
            "id": p.id,
            "workspace_id": p.workspace_id,
            "finding_id": p.finding_id,
            "target_url": p.target_url,
            "rule_id": p.rule_id,
            "rule_title": p.rule_title,
            "severity": p.severity,
            "root_cause_file": p.root_cause_file,
            "root_cause_line": p.root_cause_line,
            "patch_diff": p.patch_diff,
            "patch_hash": p.patch_hash,
            "approved_by": p.approved_by,
            "approved_at": p.approved_at,
            "before_evidence": _loads(p.before_evidence_json),
            "after_evidence": _loads(p.after_evidence_json),
            "security_replay_status": p.security_replay_status,
            "regression_test_status": p.regression_test_status,
            "verifier_verdict": p.verifier_verdict,
            "verified_at": p.verified_at,
            "proof_hash": p.proof_hash
        }

repo = Repository()

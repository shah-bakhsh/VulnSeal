"""
Remediation Human Approval & ShadowFix Execution API
Human operator approval gate and isolated digital-twin verification.
"""
from fastapi import APIRouter, HTTPException, Body
from typing import Dict, Any
from ..database.repository import repo
from ..shadowfix.engine import shadowfix_engine

router = APIRouter(tags=["Remediation"])

def _find_finding_and_patch(patch_or_finding_id: str):
    finding = repo.get_finding(patch_or_finding_id)
    if finding:
        patch = repo.get_patch_for_finding(patch_or_finding_id) or finding.get("patch")
        return finding, patch

    # Search by patch ID
    findings = repo.get_findings()
    for f in findings:
        p = f.get("patch")
        if p and p.get("id") == patch_or_finding_id:
            return f, p
    return None, None

@router.post("/api/remediations/{id}/approve")
def approve_patch(id: str, body: Dict[str, Any] = Body(...)):
    finding, patch = _find_finding_and_patch(id)
    if not finding or not patch:
        raise HTTPException(status_code=404, detail="Patch candidate or finding not found.")

    approver_email = body.get("approver_email", "operator@vulnseal.security")
    patch_hash = body.get("patch_hash")

    # Cryptographic integrity verification
    expected_hash = patch.get("sha256_hash")
    if patch_hash and patch_hash != expected_hash:
        raise HTTPException(
            status_code=400,
            detail="Approval rejected: Cryptographic patch hash does not match current patch candidate."
        )

    approval = repo.create_approval({
        "patch_id": patch.get("id"),
        "approved_by_email": approver_email,
        "approved_patch_hash": expected_hash,
        "status": "approved"
    })

    repo.update_finding(finding["id"], {
        "status": "approved",
        "approval": approval
    })

    repo.record_audit_log({
        "workspace_id": finding.get("workspace_id", "ws_default_01"),
        "action": "PATCH_APPROVED",
        "actor": approver_email,
        "resource_type": "finding",
        "resource_id": finding["id"],
        "decision": "APPROVED",
        "details": {"patch_hash": expected_hash, "finding_title": finding.get("title")}
    })

    return approval

@router.post("/api/remediations/{id}/reject")
def reject_patch(id: str, body: Dict[str, Any] = Body(...)):
    finding, patch = _find_finding_and_patch(id)
    if not finding or not patch:
        raise HTTPException(status_code=404, detail="Patch candidate not found.")

    reason = body.get("reason", "Operator rejected patch candidate.")
    approver_email = body.get("approver_email", "operator@vulnseal.security")

    approval = repo.create_approval({
        "patch_id": patch.get("id"),
        "approved_by_email": approver_email,
        "approved_patch_hash": patch.get("sha256_hash", ""),
        "status": "rejected",
        "rejection_reason": reason
    })

    repo.update_finding(finding["id"], {
        "status": "confirmed",
        "approval": approval
    })

    repo.record_audit_log({
        "workspace_id": finding.get("workspace_id", "ws_default_01"),
        "action": "PATCH_REJECTED",
        "actor": approver_email,
        "resource_type": "finding",
        "resource_id": finding["id"],
        "decision": "REJECTED",
        "details": {"reason": reason}
    })

    return approval

@router.post("/api/remediations/{id}/shadowfix")
def run_shadowfix(id: str, body: Dict[str, Any] = Body({})):
    finding, patch = _find_finding_and_patch(id)
    if not finding or not patch:
        raise HTTPException(status_code=404, detail="Finding or patch candidate not found.")

    approver_email = body.get("approver_email") or finding.get("approval", {}).get("approved_by_email", "operator@vulnseal.security")
    workspace_id = finding.get("workspace_id", "ws_default_01")

    res = shadowfix_engine.execute_sandbox_verification(
        finding=finding,
        patch=patch,
        approver_email=approver_email,
        workspace_id=workspace_id
    )

    return res

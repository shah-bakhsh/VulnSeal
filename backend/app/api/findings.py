"""
Findings & Remediation Generation API
Retrieves confirmed findings and invokes RootCauseMapper and RemediationEngineer.
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any
from ..database.repository import repo
from ..agents.root_cause_mapper import RootCauseMapperAgent
from ..agents.remediation_engineer import RemediationEngineerAgent

router = APIRouter(tags=["Findings"])

@router.get("/api/findings")
def get_findings(workspace_id: str = Query("ws_default_01")):
    return repo.get_findings(workspace_id)

@router.get("/api/findings/{finding_id}")
def get_finding(finding_id: str):
    finding = repo.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    patch = repo.get_patch_for_finding(finding_id)
    proof = repo.get_proof(finding.get("proof_id")) if finding.get("proof_id") else None

    return {
        **finding,
        "patch": patch or finding.get("patch"),
        "rootCause": finding.get("rootCause"),
        "approval": finding.get("approval"),
        "proof": proof
    }

@router.post("/api/findings/{finding_id}/remediation")
def generate_remediation(finding_id: str):
    finding = repo.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    workspace_id = finding.get("workspace_id", "ws_default_01")

    # Step 1: RootCauseMapper
    root_cause = RootCauseMapperAgent.map_root_cause(finding, workspace_id=workspace_id)

    # Step 2: RemediationEngineer
    patch = RemediationEngineerAgent.synthesize_patch(finding, root_cause, workspace_id=workspace_id)

    # Update finding state to awaiting human approval
    repo.create_patch(patch)
    repo.update_finding(finding_id, {
        "status": "waiting_approval",
        "rootCause": root_cause,
        "patch": patch
    })

    return {"rootCause": root_cause, "patch": patch}

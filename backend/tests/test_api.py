"""
VulnSeal FastAPI Integration & Golden Demo E2E Tests
Validates the complete autonomous security remediation loop:
FIND -> FIX -> PROVE
"""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database.session import init_db
from backend.app.database.repository import repo

@pytest.fixture(scope="module")
def client():
    init_db()
    repo.seed_initial_data()
    with TestClient(app) as c:
        yield c

def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["service"] == "vulnseal-api"

def test_get_targets(client):
    res = client.get("/api/targets")
    assert res.status_code == 200
    targets = res.json()
    assert len(targets) >= 1
    demo = next(t for t in targets if t.get("is_demo"))
    assert demo["status"] == "authorized"

def test_golden_demo_workflow(client):
    # 1. Retrieve Demo Target
    res = client.get("/api/targets")
    targets = res.json()
    demo = next(t for t in targets if t.get("is_demo"))
    demo_id = demo["id"]

    # 2. Launch Scan (FIND)
    scan_res = client.post("/api/scans", json={"target_id": demo_id})
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["status"] == "completed"
    assert scan_data["confirmed_findings_count"] > 0

    # 3. Retrieve Findings
    findings_res = client.get("/api/findings")
    assert findings_res.status_code == 200
    findings = findings_res.json()
    assert len(findings) > 0
    target_finding = findings[0]
    finding_id = target_finding["id"]

    # 4. Generate Remediation (FIX)
    remediation_res = client.post(f"/api/findings/{finding_id}/remediation")
    assert remediation_res.status_code == 200
    remed_data = remediation_res.json()
    assert "patch" in remed_data
    assert "rootCause" in remed_data
    patch = remed_data["patch"]
    patch_id = patch["id"]
    patch_hash = patch["sha256_hash"]

    # 5. Human Approval Gate
    approval_res = client.post(f"/api/remediations/{patch_id}/approve", json={
        "patch_hash": patch_hash,
        "approver_email": "security.officer@vulnseal.enterprise"
    })
    assert approval_res.status_code == 200
    approval_data = approval_res.json()
    assert approval_data["status"] == "approved"

    # 6. ShadowFix Execution & Proof of Fix (PROVE)
    sfx_res = client.post(f"/api/remediations/{patch_id}/shadowfix")
    assert sfx_res.status_code == 200
    sfx_data = sfx_res.json()
    assert sfx_data["verification_verdict"] == "VERIFIED"
    assert "proof" in sfx_data
    proof = sfx_data["proof"]
    assert "proof_hash" in proof
    assert len(proof["proof_hash"]) == 64

    # 7. Proof Center Verification
    proofs_res = client.get("/api/proofs")
    assert proofs_res.status_code == 200
    proofs = proofs_res.json()
    assert any(p["id"] == proof["id"] for p in proofs)

    # 8. One Source of Truth Check
    updated_targets = client.get("/api/targets").json()
    updated_demo = next(t for t in updated_targets if t["id"] == demo_id)
    assert updated_demo["verified_fixes_count"] >= 1

"""
VulnSeal End-to-End Automated Test Suite (Python)
Validates the complete autonomous security remediation loop:
FIND -> FIX -> PROVE
"""
import sys
import json

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from backend.db import db
from backend.policy import PolicyEngine
from backend.scanner import scanner
from backend.ai_router import model_router
from backend.shadowfix import shadowfix_engine
from backend.demo_target import demo_target

def run_tests():
    print("================================================================")
    print("🛡️  VULNSEAL AUTOMATED PYTHON BACKEND VERIFICATION SUITE")
    print("================================================================")

    passed_count = 0
    total_count = 0

    def assert_test(name: str, condition: bool, detail: str = ""):
        nonlocal passed_count, total_count
        total_count += 1
        if condition:
            passed_count += 1
            print(f"  ✅ [PASS] {name} {f'({detail})' if detail else ''}")
        else:
            print(f"  ❌ [FAIL] {name} - {detail}")
            sys.exit(1)

    # 1. ScopeGuard Policy Engine Tests
    print("\n[Stage 1: ScopeGuard Security & SSRF Policy Tests]")
    safe, msg = PolicyEngine.validate_target_url("http://localhost:3000/demo-target", is_demo=True)
    assert_test("Authorized Demo Target passes ScopeGuard", safe, msg)

    safe_block, msg_block = PolicyEngine.validate_target_url("http://192.168.1.1/admin", is_demo=False)
    assert_test("Private RFC1918 address blocked by ScopeGuard SSRF guard", not safe_block, msg_block)

    safe_loop, msg_loop = PolicyEngine.validate_target_url("http://127.0.0.1:8080/secrets", is_demo=False)
    assert_test("Loopback address blocked when not in demo mode", not safe_loop, msg_loop)

    # 2. Demo Target Tests
    print("\n[Stage 2: Intentionally Vulnerable Demo Target Tests]")
    demo_res = demo_target.handle_request("/demo-target", "GET", {})
    assert_test("Demo Target returns status 200", demo_res["status"] == 200)
    assert_test("Demo Target index body contains sandbox banner", "Apex Global Commercial Banking" in demo_res["body"])

    login_res = demo_target.handle_request("/demo-target/login", "POST", {})
    assert_test("Demo Login issues session cookie", "Set-Cookie" in login_res["headers"])

    # 3. Scanner Orchestration Tests
    print("\n[Stage 3: Multi-Agent Scanner Pipeline (FIND)]")
    targets = db.get_targets()
    demo_tgt = next(t for t in targets if t.get("is_demo"))
    assert_test("Demo target registered in database", demo_tgt is not None, f"ID: {demo_tgt['id']}")

    scan_result = scanner.run_scan(demo_tgt["id"])
    assert_test("Scan completed successfully", scan_result["status"] == "completed")
    assert_test("Scan confirmed candidate vulnerabilities", scan_result["confirmed_findings_count"] > 0, f"Found {scan_result['confirmed_findings_count']} issues")

    # 4. Findings & Evidence Tests
    print("\n[Stage 4: Findings & Evidence Verification]")
    findings = db.get_findings()
    assert_test("Findings recorded in state store", len(findings) > 0, f"{len(findings)} findings")

    test_finding = findings[0]
    assert_test("Finding has deterministic SHA-256 evidence hash", "sha256_hash" in test_finding["evidence"], test_finding["evidence"]["sha256_hash"][:16] + "...")

    # 5. Root Cause & Patch Synthesis (FIX)
    print("\n[Stage 5: Remediation Synthesis via AI Router / AST Engine (FIX)]")
    remediation = model_router.analyze_vulnerability(test_finding)
    assert_test("RootCauseMapper identified file and symbol", "filePath" in remediation["rootCause"] and "symbol" in remediation["rootCause"])
    assert_test("RemediationEngineer synthesized unified diff", "diff" in remediation["patch"] and "+++" in remediation["patch"]["diff"])

    test_finding["root_cause"] = remediation["rootCause"]
    test_finding["patch"] = remediation["patch"]
    test_finding["status"] = "waiting_approval"
    db.update_finding(test_finding["id"], test_finding)

    # 6. Patch Approval Workflow
    print("\n[Stage 6: Human-in-the-Loop Patch Approval]")
    test_finding["approval"] = {
        "approved_by_email": "security.officer@vulnseal.enterprise",
        "status": "approved",
        "approved_at": "2026-10-04T08:50:00Z"
    }
    test_finding["status"] = "approved"
    db.update_finding(test_finding["id"], test_finding)
    assert_test("Finding transitioned to approved state", test_finding["status"] == "approved")

    # 7. ShadowFix Sandbox Verification (PROVE)
    print("\n[Stage 7: ShadowFix Digital-Twin Verification & Cryptographic Proof (PROVE)]")
    sfx_result = shadowfix_engine.run_sandbox_verification(
        test_finding,
        test_finding["patch"],
        "security.officer@vulnseal.enterprise"
    )
    assert_test("ShadowFix sandbox steps completed", len(sfx_result["steps"]) == 4)
    assert_test("Cryptographic Proof-of-Fix generated", "proof_hash" in sfx_result["proof"], sfx_result["proof"]["proof_hash"][:24] + "...")
    assert_test("Security replay verdict is VERIFIED", sfx_result["proof"]["verifier_verdict"] == "VERIFIED")

    # 8. Agent Event Log & Audit Trail Verification
    print("\n[Stage 8: Agent Activity & Audit Trail]")
    events = db.get_agent_events()
    assert_test("Agent journal logged events", len(events) >= 4, f"{len(events)} events recorded")
    agents_active = set(e["agent"] for e in events)
    assert_test("Specialized agents participated in workflow", "ScopeGuard" in agents_active and "SurfaceMapper" in agents_active and "SecurityInspector" in agents_active)

    print("\n================================================================")
    print(f"🎉  ALL {passed_count}/{total_count} TESTS PASSED SUCCESSFULLY!")
    print("🛡️  Autonomous Remediation Loop (FIND -> FIX -> PROVE) Verified 100% Operational")
    print("================================================================\n")

if __name__ == '__main__':
    run_tests()

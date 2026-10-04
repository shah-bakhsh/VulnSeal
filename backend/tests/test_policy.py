"""
VulnSeal Policy & NetworkGuard Security Tests
Validates SSRF defense, loopback restrictions, and strict Demo Lab exceptions.
"""
import pytest
from backend.app.security.network_guard import NetworkGuard

def test_public_https_target_allowed():
    allowed, reason, rule = NetworkGuard.evaluate_target_url("https://example.com/api/test")
    assert allowed is True
    assert rule == "POLICY_PASS"

def test_private_rfc1918_ip_blocked():
    allowed, reason, rule = NetworkGuard.evaluate_target_url("http://10.0.0.1/admin")
    assert allowed is False
    assert rule == "SSRF_PRIVATE_IP_BLOCKED"

def test_cloud_metadata_blocked():
    allowed, reason, rule = NetworkGuard.evaluate_target_url("http://169.254.169.254/latest/meta-data")
    assert allowed is False
    assert rule == "SSRF_PRIVATE_IP_BLOCKED"

def test_normal_localhost_blocked():
    allowed, reason, rule = NetworkGuard.evaluate_target_url("http://127.0.0.1:8080/secrets", is_demo=False)
    assert allowed is False
    assert "SSRF" in reason or "Direct private" in reason

def test_demo_sandbox_exception_allowed():
    allowed, reason, rule = NetworkGuard.evaluate_target_url("http://localhost:3000/demo-target", is_demo=True)
    assert allowed is True
    assert rule == "DEMO_SANDBOX_AUTHORIZED"

def test_demo_sandbox_out_of_scope_path_blocked():
    allowed, reason, rule = NetworkGuard.evaluate_target_url("http://localhost:3000/admin", is_demo=True)
    assert allowed is False
    assert rule == "OUT_OF_SCOPE_DEMO_PATH"

def test_demo_sandbox_foreign_host_blocked():
    allowed, reason, rule = NetworkGuard.evaluate_target_url("http://192.168.1.1/demo-target", is_demo=True)
    assert allowed is False
    assert rule == "OUT_OF_SCOPE_DEMO_HOST"

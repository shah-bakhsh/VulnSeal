"""
Deterministic Security Rules Tests
"""
import pytest
from backend.app.security.rules.cookie_rule import CookieSecurityRule
from backend.app.security.rules.cors_rule import CorsSecurityRule
from backend.app.security.rules.headers_rule import HeadersSecurityRule
from backend.app.security.redaction import EvidenceRedactor

def test_detects_insecure_session_cookie():
    headers = {"Set-Cookie": "session_id=vs_secret_token_1234; Path=/; HttpOnly"}
    findings = CookieSecurityRule.execute("https://bank.example.com/login", headers, "{}", 200)
    secure_findings = [f for f in findings if "SECURE" in f["rule_id"]]
    assert len(secure_findings) == 1
    assert "Secure" in secure_findings[0]["evidence"]["raw_attribute_missing"]
    assert "vs_secret_token_1234" not in secure_findings[0]["evidence"]["sanitized_excerpt"]

def test_passes_secure_session_cookie():
    headers = {"Set-Cookie": "session_id=vs_secret_token_1234; Path=/; HttpOnly; Secure"}
    findings = CookieSecurityRule.execute("https://bank.example.com/login", headers, "{}", 200)
    assert len(findings) == 0

def test_detects_permissive_cors():
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true"
    }
    findings = CorsSecurityRule.execute("https://api.example.com/data", headers, "{}", 200)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "RULE-CORS-001"

def test_detects_missing_csp():
    headers = {"Content-Type": "text/html"}
    findings = HeadersSecurityRule.execute("https://app.example.com/", headers, "<html></html>", 200)
    csp_findings = [f for f in findings if "CSP" in f["rule_id"]]
    assert len(csp_findings) == 1

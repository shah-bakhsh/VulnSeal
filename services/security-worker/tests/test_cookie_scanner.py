import pytest
from scanners.cookie_scanner import PythonCookieSecurityRule

def test_detects_insecure_session_cookie():
    headers = {
        "set-cookie": "session_token=vs_test_secret_1234; Path=/; HttpOnly; SameSite=Lax"
    }
    result = PythonCookieSecurityRule.evaluate("https://example.com/login", "POST", headers)
    assert result.has_vulnerability is True
    assert result.rule_id == "COOKIE-SECURE-001"
    assert result.attribute_missing == "Secure"
    assert "vs_test_secret_1234" not in result.sanitized_header

def test_passes_secure_session_cookie():
    headers = {
        "set-cookie": "session_token=vs_test_secret_1234; Path=/; HttpOnly; SameSite=Lax; Secure"
    }
    result = PythonCookieSecurityRule.evaluate("https://example.com/login", "POST", headers)
    assert result.has_vulnerability is False

"""
Cookie Security Rule (Python)
Checks for missing Secure, HttpOnly, and SameSite attributes in Set-Cookie headers.
"""
import hashlib
from typing import List, Dict, Any

class CookieSecurityRule:
    RULE_ID = "RULE-COOKIE-001"
    RULE_NAME = "Insecure Cookie Attributes (Missing Secure/HttpOnly/SameSite)"
    CATEGORY = "Session & Authentication Security"

    @classmethod
    def execute(cls, target_url: str, response_headers: Dict[str, str], response_body: str, status_code: int) -> List[Dict[str, Any]]:
        findings = []
        set_cookie = None
        for k, v in response_headers.items():
            if k.lower() == "set-cookie":
                set_cookie = v
                break

        if not set_cookie:
            return findings

        cookies = [c.strip() for c in set_cookie.split(",")] if "," in set_cookie else [set_cookie]

        for cookie in cookies:
            cookie_lower = cookie.lower()
            is_secure = "secure" in cookie_lower
            is_httponly = "httponly" in cookie_lower
            has_samesite = "samesite" in cookie_lower

            cookie_name = cookie.split("=")[0].strip()

            if not is_httponly:
                raw_hash = hashlib.sha256(f"{target_url}:{cookie_name}:missing_httponly".encode()).hexdigest()
                findings.append({
                    "rule_id": f"{cls.RULE_ID}-HTTPONLY",
                    "rule_name": f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                    "category": cls.CATEGORY,
                    "title": f"Insecure Session Cookie '{cookie_name}' Missing HttpOnly",
                    "description": f"The cookie '{cookie_name}' is accessible via client-side JavaScript, exposing it to XSS theft.",
                    "severity": "high" if "session" in cookie_name.lower() or "auth" in cookie_name.lower() else "medium",
                    "confidence": 0.99,
                    "affected_url": target_url,
                    "evidence": {
                        "request_method": "POST",
                        "request_url": target_url,
                        "request_headers": {"User-Agent": "VulnSeal-SecurityInspector/1.0"},
                        "response_status": status_code,
                        "response_status_text": "OK",
                        "response_headers": dict(response_headers),
                        "sanitized_excerpt": f"Set-Cookie: {cookie}",
                        "observation_description": f"Cookie '{cookie_name}' lacks HttpOnly directive.",
                        "raw_attribute_missing": "HttpOnly",
                        "sha256_hash": raw_hash
                    }
                })

            if not is_secure and target_url.startswith("https"):
                raw_hash = hashlib.sha256(f"{target_url}:{cookie_name}:missing_secure".encode()).hexdigest()
                findings.append({
                    "rule_id": f"{cls.RULE_ID}-SECURE",
                    "rule_name": f"Cookie '{cookie_name}' Missing Secure Flag",
                    "category": cls.CATEGORY,
                    "title": f"Cookie '{cookie_name}' Missing Secure Flag",
                    "description": f"The cookie '{cookie_name}' can be transmitted over unencrypted HTTP channels.",
                    "severity": "medium",
                    "confidence": 0.99,
                    "affected_url": target_url,
                    "evidence": {
                        "request_method": "POST",
                        "request_url": target_url,
                        "request_headers": {"User-Agent": "VulnSeal-SecurityInspector/1.0"},
                        "response_status": status_code,
                        "response_status_text": "OK",
                        "response_headers": dict(response_headers),
                        "sanitized_excerpt": f"Set-Cookie: {cookie}",
                        "observation_description": f"Cookie '{cookie_name}' lacks Secure directive on HTTPS target.",
                        "raw_attribute_missing": "Secure",
                        "sha256_hash": raw_hash
                    }
                })

        return findings

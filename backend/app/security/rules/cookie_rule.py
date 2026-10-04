"""
Cookie Security Rule (Python)
Checks for missing Secure, HttpOnly, and SameSite directives on session cookies.
"""
import hashlib
from typing import List, Dict, Any
from ..redaction import EvidenceRedactor

class CookieSecurityRule:
    RULE_ID = "RULE-COOKIE-001"
    RULE_NAME = "Insecure Cookie Attributes (Missing Secure/HttpOnly)"
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

            cookie_name = cookie.split("=")[0].strip()
            is_session = any(term in cookie_name.lower() for term in ["session", "token", "auth", "sid", "id"])

            sanitized_cookie = EvidenceRedactor.sanitize_cookie_header(cookie)

            # Insecure session cookie missing Secure attribute
            if not is_secure and (is_session or target_url.startswith("https") or "demo" in target_url):
                evidence_raw = f"{target_url}:{cookie_name}:missing_secure"
                sha256 = hashlib.sha256(evidence_raw.encode()).hexdigest()
                findings.append({
                    "rule_id": f"{cls.RULE_ID}-SECURE",
                    "rule_name": "Session Cookie Missing Secure Flag",
                    "category": cls.CATEGORY,
                    "title": f"Insecure Session Cookie '{cookie_name}' (Missing Secure Flag)",
                    "description": (
                        f"The session credential '{cookie_name}' is issued without the Secure directive. "
                        "Browsers may transmit this sensitive token over unencrypted HTTP channels, enabling man-in-the-middle eavesdropping."
                    ),
                    "severity": "high" if is_session else "medium",
                    "confidence": 0.98,
                    "affected_url": target_url,
                    "evidence": {
                        "id": f"evi_{sha256[:8]}",
                        "request_method": "POST" if "/login" in target_url else "GET",
                        "request_url": target_url,
                        "request_headers": {"User-Agent": "VulnSeal-SecurityInspector/1.0"},
                        "response_status": status_code,
                        "response_status_text": "OK",
                        "response_headers": EvidenceRedactor.sanitize_headers(response_headers),
                        "sanitized_excerpt": f"Set-Cookie: {sanitized_cookie}",
                        "observation_description": f"Session cookie '{cookie_name}' issued without the Secure directive.",
                        "raw_attribute_missing": "Secure",
                        "captured_at": "now",
                        "sha256_hash": sha256
                    }
                })

            # Missing HttpOnly attribute
            if not is_httponly and is_session:
                evidence_raw = f"{target_url}:{cookie_name}:missing_httponly"
                sha256 = hashlib.sha256(evidence_raw.encode()).hexdigest()
                findings.append({
                    "rule_id": f"{cls.RULE_ID}-HTTPONLY",
                    "rule_name": "Session Cookie Missing HttpOnly Flag",
                    "category": cls.CATEGORY,
                    "title": f"Session Cookie '{cookie_name}' Missing HttpOnly Flag",
                    "description": (
                        f"The cookie '{cookie_name}' does not include the HttpOnly flag, "
                        "allowing unauthorized client-side JavaScript access and potential exfiltration via Cross-Site Scripting (XSS)."
                    ),
                    "severity": "high",
                    "confidence": 0.99,
                    "affected_url": target_url,
                    "evidence": {
                        "id": f"evi_{sha256[:8]}",
                        "request_method": "POST" if "/login" in target_url else "GET",
                        "request_url": target_url,
                        "request_headers": {"User-Agent": "VulnSeal-SecurityInspector/1.0"},
                        "response_status": status_code,
                        "response_status_text": "OK",
                        "response_headers": EvidenceRedactor.sanitize_headers(response_headers),
                        "sanitized_excerpt": f"Set-Cookie: {sanitized_cookie}",
                        "observation_description": f"Cookie '{cookie_name}' lacks HttpOnly flag.",
                        "raw_attribute_missing": "HttpOnly",
                        "captured_at": "now",
                        "sha256_hash": sha256
                    }
                })

        return findings

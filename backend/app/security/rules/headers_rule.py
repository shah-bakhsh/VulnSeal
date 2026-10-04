"""
Security Headers Rule (Python)
Checks for missing HSTS, CSP, and X-Frame-Options defensive response headers.
"""
import hashlib
from typing import List, Dict, Any
from ..redaction import EvidenceRedactor

class HeadersSecurityRule:
    CATEGORY = "HTTP Transport & Defensive Headers"

    @classmethod
    def execute(cls, target_url: str, response_headers: Dict[str, str], response_body: str, status_code: int) -> List[Dict[str, Any]]:
        findings = []
        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        # 1. Content Security Policy (CSP)
        if "content-security-policy" not in headers_lower:
            sha256 = hashlib.sha256(f"{target_url}:missing_csp".encode()).hexdigest()
            findings.append({
                "rule_id": "RULE-HEADER-CSP-001",
                "rule_name": "Missing Content-Security-Policy (CSP) Header",
                "category": cls.CATEGORY,
                "title": "Missing Content-Security-Policy (CSP) Defense",
                "description": (
                    "Target does not transmit a Content-Security-Policy header. "
                    "Without CSP, the browser lacks defense-in-depth against Cross-Site Scripting (XSS) and code injection attacks."
                ),
                "severity": "medium",
                "confidence": 0.95,
                "affected_url": target_url,
                "evidence": {
                    "id": f"evi_{sha256[:8]}",
                    "request_method": "GET",
                    "request_url": target_url,
                    "request_headers": {"User-Agent": "VulnSeal-SecurityInspector/1.0"},
                    "response_status": status_code,
                    "response_status_text": "OK",
                    "response_headers": EvidenceRedactor.sanitize_headers(response_headers),
                    "sanitized_excerpt": "Missing Header: Content-Security-Policy",
                    "observation_description": "Server response omitted Content-Security-Policy header.",
                    "raw_attribute_missing": "Content-Security-Policy",
                    "captured_at": "now",
                    "sha256_hash": sha256
                }
            })

        # 2. X-Frame-Options (Clickjacking)
        if "x-frame-options" not in headers_lower and "content-security-policy" not in headers_lower:
            sha256 = hashlib.sha256(f"{target_url}:missing_xfo".encode()).hexdigest()
            findings.append({
                "rule_id": "RULE-HEADER-XFO-001",
                "rule_name": "Missing X-Frame-Options Header",
                "category": cls.CATEGORY,
                "title": "Missing X-Frame-Options Clickjacking Protection",
                "description": (
                    "Target omits X-Frame-Options or frame-ancestors directive. "
                    "This permits third-party framing inside iframe elements, exposing users to clickjacking UI redress attacks."
                ),
                "severity": "medium",
                "confidence": 0.95,
                "affected_url": target_url,
                "evidence": {
                    "id": f"evi_{sha256[:8]}",
                    "request_method": "GET",
                    "request_url": target_url,
                    "request_headers": {"User-Agent": "VulnSeal-SecurityInspector/1.0"},
                    "response_status": status_code,
                    "response_status_text": "OK",
                    "response_headers": EvidenceRedactor.sanitize_headers(response_headers),
                    "sanitized_excerpt": "Missing Header: X-Frame-Options",
                    "observation_description": "Target response lacks X-Frame-Options framing directive.",
                    "raw_attribute_missing": "X-Frame-Options",
                    "captured_at": "now",
                    "sha256_hash": sha256
                }
            })

        # 3. Strict-Transport-Security (HSTS) on HTTPS endpoints
        if target_url.startswith("https") and "strict-transport-security" not in headers_lower:
            sha256 = hashlib.sha256(f"{target_url}:missing_hsts".encode()).hexdigest()
            findings.append({
                "rule_id": "RULE-HEADER-HSTS-001",
                "rule_name": "Missing Strict-Transport-Security (HSTS) Header",
                "category": cls.CATEGORY,
                "title": "Missing Strict-Transport-Security (HSTS) Enforcement",
                "description": (
                    "HTTPS target does not enforce HTTP Strict Transport Security. "
                    "Unsecured initial connections remain susceptible to SSL stripping and protocol downgrade attacks."
                ),
                "severity": "medium",
                "confidence": 1.0,
                "affected_url": target_url,
                "evidence": {
                    "id": f"evi_{sha256[:8]}",
                    "request_method": "GET",
                    "request_url": target_url,
                    "request_headers": {"User-Agent": "VulnSeal-SecurityInspector/1.0"},
                    "response_status": status_code,
                    "response_status_text": "OK",
                    "response_headers": EvidenceRedactor.sanitize_headers(response_headers),
                    "sanitized_excerpt": "Missing Header: Strict-Transport-Security",
                    "observation_description": "Target response lacks HSTS header on HTTPS.",
                    "raw_attribute_missing": "Strict-Transport-Security",
                    "captured_at": "now",
                    "sha256_hash": sha256
                }
            })

        return findings

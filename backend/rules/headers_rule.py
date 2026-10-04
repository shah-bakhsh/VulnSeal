"""
Headers Security Rule (Python)
Checks for missing HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options.
"""
import hashlib
import json
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional

class HeadersSecurityRule:
    RULE_ID = "RULE-SEC-001"
    RULE_NAME = "Missing Standard HTTP Security Headers"
    CATEGORY = "HTTP Security & Defense-in-Depth"

    REQUIRED_HEADERS = [
        {
            "name": "strict-transport-security",
            "title": "Missing Strict-Transport-Security (HSTS)",
            "severity": "medium",
            "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "desc": "The server does not enforce HTTPS connections via HSTS header."
        },
        {
            "name": "content-security-policy",
            "title": "Missing Content-Security-Policy (CSP)",
            "severity": "high",
            "fix": "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
            "desc": "No Content-Security-Policy header detected to restrict script execution and prevent XSS."
        },
        {
            "name": "x-frame-options",
            "title": "Missing X-Frame-Options (Clickjacking Risk)",
            "severity": "medium",
            "fix": "X-Frame-Options: DENY",
            "desc": "The page can be embedded in an iframe on third-party sites, exposing users to clickjacking."
        },
        {
            "name": "x-content-type-options",
            "title": "Missing X-Content-Type-Options",
            "severity": "low",
            "fix": "X-Content-Type-Options: nosniff",
            "desc": "MIME-sniffing protection is not enabled, allowing browsers to execute disguised payloads."
        }
    ]

    @classmethod
    def execute(cls, target_url: str, response_headers: Dict[str, str], response_body: str, status_code: int) -> List[Dict[str, Any]]:
        findings = []
        lower_headers = {k.lower(): v for k, v in response_headers.items()}

        for req in cls.REQUIRED_HEADERS:
            h_name = req["name"]
            if h_name not in lower_headers:
                raw_hash = hashlib.sha256(f"{target_url}:{h_name}:missing".encode()).hexdigest()
                findings.append({
                    "rule_id": f"{cls.RULE_ID}-{h_name.upper()}",
                    "rule_name": req["title"],
                    "category": cls.CATEGORY,
                    "title": req["title"],
                    "description": req["desc"],
                    "severity": req["severity"],
                    "confidence": 0.98,
                    "affected_url": target_url,
                    "evidence": {
                        "request_method": "GET",
                        "request_url": target_url,
                        "request_headers": {"User-Agent": "VulnSeal-SecurityInspector/1.0"},
                        "response_status": status_code,
                        "response_status_text": "OK" if status_code == 200 else str(status_code),
                        "response_headers": dict(response_headers),
                        "sanitized_excerpt": f"Observed response missing mandatory header '{h_name}'",
                        "observation_description": f"Target response lacks '{h_name}'. Recommended directive: '{req['fix']}'.",
                        "raw_attribute_missing": h_name,
                        "sha256_hash": raw_hash
                    }
                })

        return findings

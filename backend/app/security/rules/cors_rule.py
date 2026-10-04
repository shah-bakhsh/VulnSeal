"""
CORS Security Rule (Python)
Checks for overly permissive Cross-Origin Resource Sharing configurations.
"""
import hashlib
from typing import List, Dict, Any
from ..redaction import EvidenceRedactor

class CorsSecurityRule:
    RULE_ID = "RULE-CORS-001"
    RULE_NAME = "Permissive CORS Origin Wildcard with Credentials"
    CATEGORY = "API & Origin Security"

    @classmethod
    def execute(cls, target_url: str, response_headers: Dict[str, str], response_body: str, status_code: int) -> List[Dict[str, Any]]:
        findings = []
        allow_origin = None
        allow_creds = None

        for k, v in response_headers.items():
            k_lower = k.lower()
            if k_lower == "access-control-allow-origin":
                allow_origin = v.strip()
            elif k_lower == "access-control-allow-credentials":
                allow_creds = v.strip().lower()

        # Vulnerable pattern: Wildcard origin with credentials allowed
        if allow_origin == "*" and allow_creds == "true":
            evidence_raw = f"{target_url}:cors_wildcard_with_creds"
            sha256 = hashlib.sha256(evidence_raw.encode()).hexdigest()
            findings.append({
                "rule_id": cls.RULE_ID,
                "rule_name": cls.RULE_NAME,
                "category": cls.CATEGORY,
                "title": "Permissive CORS Origin Wildcard with Credentials Enabled",
                "description": (
                    "The endpoint specifies 'Access-Control-Allow-Origin: *' combined with 'Access-Control-Allow-Credentials: true'. "
                    "This invalid or overly permissive combination violates origin security bounds and can permit cross-origin exfiltration."
                ),
                "severity": "high",
                "confidence": 1.0,
                "affected_url": target_url,
                "evidence": {
                    "id": f"evi_{sha256[:8]}",
                    "request_method": "GET",
                    "request_url": target_url,
                    "request_headers": {"User-Agent": "VulnSeal-SecurityInspector/1.0", "Origin": "https://attacker-origin.example.com"},
                    "response_status": status_code,
                    "response_status_text": "OK",
                    "response_headers": EvidenceRedactor.sanitize_headers(response_headers),
                    "sanitized_excerpt": "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                    "observation_description": "Server returned wildcard origin with credentials enabled.",
                    "raw_attribute_missing": "Explicit CORS Origin Restriction",
                    "captured_at": "now",
                    "sha256_hash": sha256
                }
            })

        return findings

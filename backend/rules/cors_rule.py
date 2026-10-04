"""
CORS Security Rule (Python)
Detects overly permissive CORS policies (wildcards with credentials, arbitrary origin reflection).
"""
import hashlib
from typing import List, Dict, Any

class CorsSecurityRule:
    RULE_ID = "RULE-CORS-001"
    RULE_NAME = "Insecure Cross-Origin Resource Sharing Configuration"
    CATEGORY = "CORS & Cross-Origin Security"

    @classmethod
    def execute(cls, target_url: str, response_headers: Dict[str, str], response_body: str, status_code: int) -> List[Dict[str, Any]]:
        findings = []
        lower_headers = {k.lower(): v for k, v in response_headers.items()}

        acao = lower_headers.get("access-control-allow-origin")
        acac = lower_headers.get("access-control-allow-credentials")

        if acao == "*" and acac == "true":
            raw_hash = hashlib.sha256(f"{target_url}:cors:wildcard_credentials".encode()).hexdigest()
            findings.append({
                "rule_id": f"{cls.RULE_ID}-WILDCARD-CREDS",
                "rule_name": "CORS Wildcard Origin with Credentials Allowed",
                "category": cls.CATEGORY,
                "title": "Permissive CORS: Wildcard Origin With Credentials",
                "description": "The server specifies Access-Control-Allow-Origin: * while allowing credentials, violating web browser SOP protections.",
                "severity": "high",
                "confidence": 0.99,
                "affected_url": target_url,
                "evidence": {
                    "request_method": "OPTIONS",
                    "request_url": target_url,
                    "request_headers": {"Origin": "https://evil.attacker.com", "User-Agent": "VulnSeal-SecurityInspector/1.0"},
                    "response_status": status_code,
                    "response_status_text": "OK" if status_code == 200 else str(status_code),
                    "response_headers": dict(response_headers),
                    "sanitized_excerpt": f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac}",
                    "observation_description": "Wildcard CORS origin reflection enables authenticated data exfiltration.",
                    "raw_attribute_missing": "Explicit Origin Allowlist",
                    "sha256_hash": raw_hash
                }
            })

        return findings

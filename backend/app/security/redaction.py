"""
VulnSeal Evidence Redaction & Sanitization
Redacts session tokens, authorization keys, passwords, and secrets before storage.
"""
import re
from typing import Dict, Any

class EvidenceRedactor:
    COOKIE_VALUE_RE = re.compile(r"(=)([^;]+)")
    BEARER_TOKEN_RE = re.compile(r"(Bearer\s+)(\S+)", re.IGNORECASE)
    API_KEY_RE = re.compile(r"((?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?)([^\"'\s,;]+)", re.IGNORECASE)

    @classmethod
    def sanitize_cookie_header(cls, raw_header: str) -> str:
        if not raw_header:
            return ""
        # Redact the cookie value portion
        return cls.COOKIE_VALUE_RE.sub(r"\1••••••••", raw_header)

    @classmethod
    def sanitize_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        sanitized = {}
        for k, v in headers.items():
            k_lower = k.lower()
            if k_lower == "set-cookie":
                sanitized[k] = cls.sanitize_cookie_header(v)
            elif k_lower in ("authorization", "cookie"):
                sanitized[k] = "[REDACTED_CREDENTIAL]"
            else:
                sanitized[k] = v
        return sanitized

    @classmethod
    def sanitize_excerpt(cls, text: str) -> str:
        if not text:
            return ""
        res = cls.COOKIE_VALUE_RE.sub(r"\1••••••••", text)
        res = cls.BEARER_TOKEN_RE.sub(r"\1••••••••", res)
        return res

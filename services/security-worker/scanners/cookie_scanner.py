import re
import hashlib
from typing import Dict, Optional, Tuple
from pydantic import BaseModel

class CookieCheckResult(BaseModel):
    has_vulnerability: bool = False
    rule_id: str
    rule_name: str
    category: str
    title: str
    description: str
    severity: str
    confidence: float
    sanitized_header: Optional[str] = None
    sha256_hash: Optional[str] = None
    attribute_missing: Optional[str] = None

class PythonCookieSecurityRule:
    RULE_ID = "COOKIE-SECURE-001"
    RULE_NAME = "Insecure Session Cookie (Missing Secure Flag)"

    @classmethod
    def sanitize(cls, raw_cookie: str) -> str:
        # Mask sensitive token value
        return re.sub(r"(=)([^;]+)", r"\1••••••••", raw_cookie)

    @classmethod
    def evaluate(cls, url: str, method: str, headers: Dict[str, str]) -> CookieCheckResult:
        set_cookie = None
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                set_cookie = v
                break

        if not set_cookie:
            return CookieCheckResult(
                has_vulnerability=False,
                rule_id=cls.RULE_ID,
                rule_name=cls.RULE_NAME,
                category="Session Management",
                title="No Set-Cookie Present",
                description="No Set-Cookie header detected.",
                severity="high",
                confidence=0.0
            )

        parts = [p.strip() for p in set_cookie.split(";")]
        name_val = parts[0]
        cookie_name = name_val.split("=")[0].lower() if "=" in name_val else ""

        is_session = any(term in cookie_name for term in ["session", "token", "auth", "sid", "id"])
        has_secure = any(p.lower() == "secure" for p in parts)

        if is_session and not has_secure:
            sanitized = cls.sanitize(set_cookie)
            sha256 = hashlib.sha256(f"{url}|{method}|{sanitized}".encode()).hexdigest()
            return CookieCheckResult(
                has_vulnerability=True,
                rule_id=cls.RULE_ID,
                rule_name=cls.RULE_NAME,
                category="Session Management",
                title="Session Cookie Missing Secure Flag",
                description="Session credential issued without the Secure directive, enabling transmission over unencrypted HTTP.",
                severity="high",
                confidence=0.98,
                sanitized_header=sanitized,
                sha256_hash=sha256,
                attribute_missing="Secure"
            )

        return CookieCheckResult(
            has_vulnerability=False,
            rule_id=cls.RULE_ID,
            rule_name=cls.RULE_NAME,
            category="Session Management",
            title="Session Cookie Secure Flag Verified",
            description="Cookie includes Secure flag.",
            severity="high",
            confidence=1.0
        )

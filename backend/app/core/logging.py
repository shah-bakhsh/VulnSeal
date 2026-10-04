"""
VulnSeal Structured Logging
Redacts credentials, cookies, and tokens before emitting logs.
"""
import logging
import re
import sys

# Windows UTF-8 console output handler
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

class RedactingFormatter(logging.Formatter):
    SENSITIVE_PATTERNS = [
        re.compile(r'(api[-_]?key\s*[:=]\s*["\']?)([^"\'\s]+)', re.IGNORECASE),
        re.compile(r'(token\s*[:=]\s*["\']?)([^"\'\s]+)', re.IGNORECASE),
        re.compile(r'(password\s*[:=]\s*["\']?)([^"\'\s]+)', re.IGNORECASE),
        re.compile(r'(Set-Cookie:\s*[^=]+=)([^;]+)', re.IGNORECASE),
        re.compile(r'(Authorization:\s*Bearer\s+)(\S+)', re.IGNORECASE),
    ]

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        for pattern in self.SENSITIVE_PATTERNS:
            msg = pattern.sub(r'\1[REDACTED]', msg)
        return msg

logger = logging.getLogger("vulnseal")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = RedactingFormatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

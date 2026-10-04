"""
VulnSeal Intentionally Vulnerable Demo Target (Python)
Provides a controlled local environment for authentic security scans and autonomous remediation tests.
"""
import json
from typing import Dict, Any

class DemoBankingTarget:
    def __init__(self):
        self.config = {
            "hsts_enabled": False,
            "csp_enabled": False,
            "xfo_enabled": False,
            "cookie_httponly": False,
            "cookie_secure": False,
            "cors_wildcard_with_creds": True
        }

    def reset_config(self):
        self.config = {
            "hsts_enabled": False,
            "csp_enabled": False,
            "xfo_enabled": False,
            "cookie_httponly": False,
            "cookie_secure": False,
            "cors_wildcard_with_creds": True
        }

    def get_index_html(self) -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VulnSeal Vulnerable Demo Banking Portal</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; max-width: 650px; margin: auto; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1.5rem; }
    h1 { color: #38bdf8; font-size: 1.3rem; margin-top: 0; }
    .badge { display: inline-block; background: #ef4444; color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
    input, button { display: block; width: 100%; margin-top: 0.75rem; padding: 0.5rem; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: white; box-sizing: border-box; }
    button { background: #2563eb; color: white; border: none; font-weight: 600; cursor: pointer; }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">SANDBOX TARGET</span>
    <h1>Apex Global Commercial Banking (Demo)</h1>
    <p style="font-size: 0.85rem; color: #94a3b8;">Deliberately vulnerable sandbox managed by VulnSeal ScopeGuard.</p>
    <form action="/demo-target/login" method="POST">
      <input type="text" name="username" value="operator@vulnseal.demo" readonly />
      <input type="password" name="password" value="demo-password-123" readonly />
      <button type="submit">Sign In to Dashboard</button>
    </form>
  </div>
</body>
</html>"""

    def handle_request(self, path: str, method: str, headers: Dict[str, str]) -> Dict[str, Any]:
        resp_headers = {"Content-Type": "text/html; charset=utf-8"}

        if self.config["hsts_enabled"]:
            resp_headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if self.config["csp_enabled"]:
            resp_headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
        if self.config["xfo_enabled"]:
            resp_headers["X-Frame-Options"] = "DENY"

        if self.config["cors_wildcard_with_creds"]:
            resp_headers["Access-Control-Allow-Origin"] = "*"
            resp_headers["Access-Control-Allow-Credentials"] = "true"

        if path.endswith("/login") and method == "POST":
            cookie_parts = ["session_id=vuln_session_token_xyz987", "Path=/"]
            if self.config["cookie_httponly"]:
                cookie_parts.append("HttpOnly")
            if self.config["cookie_secure"]:
                cookie_parts.append("Secure")
            resp_headers["Set-Cookie"] = "; ".join(cookie_parts)
            return {
                "status": 200,
                "headers": resp_headers,
                "body": json.dumps({"status": "authenticated", "user": "operator@vulnseal.demo"})
            }

        return {
            "status": 200,
            "headers": resp_headers,
            "body": self.get_index_html()
        }

demo_target = DemoBankingTarget()

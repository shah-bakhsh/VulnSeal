"""
VulnSeal Supabase Integration (Python)
Checks Supabase PostgreSQL connection status and provides database helper functions.
"""
import os
import urllib.request
import urllib.error
import json
from typing import Dict, Any

class SupabaseClient:
    def __init__(self):
        self.url = os.environ.get("SUPABASE_URL", "")
        self.key = os.environ.get("SUPABASE_ANON_KEY") or os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

    def is_configured(self) -> bool:
        return bool(self.url and self.key)

    def test_connection(self) -> Dict[str, Any]:
        if not self.is_configured():
            return {
                "success": False,
                "configured": False,
                "message": "Supabase environment variables (SUPABASE_URL, SUPABASE_ANON_KEY) are not set."
            }

        try:
            req = urllib.request.Request(
                f"{self.url.rstrip('/')}/rest/v1/",
                headers={
                    "apikey": self.key,
                    "Authorization": f"Bearer {self.key}"
                }
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return {
                    "success": resp.status in (200, 204),
                    "configured": True,
                    "status_code": resp.status,
                    "message": "Successfully connected to Supabase PostgreSQL REST gateway."
                }
        except Exception as e:
            return {
                "success": False,
                "configured": True,
                "message": f"Connection attempt returned notice: {str(e)}"
            }

supabase_client = SupabaseClient()

"""
VulnSeal NetworkGuard & Policy Engine
Central guarded network boundary enforcing origin scope, SSRF firewall,
DNS rebinding prevention, and the strict Demo Lab exception.
"""
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, Dict, Any, Optional
import httpx
from ..core.config import settings
from ..core.logging import logger

class NetworkGuard:
    @staticmethod
    def is_private_or_restricted_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return (
                ip.is_private or
                ip.is_loopback or
                ip.is_link_local or
                ip.is_reserved or
                ip.is_multicast or
                str(ip).startswith("0.") or
                str(ip) == "169.254.169.254"  # Cloud metadata
            )
        except ValueError:
            return True

    @classmethod
    def evaluate_target_url(cls, url: str, is_demo: bool = False) -> Tuple[bool, str, Optional[str]]:
        """
        Validates target URL against safety invariants.
        Returns: (allowed: bool, reason: str, rule_id: Optional[str])
        """
        if not url or not url.strip():
            return False, "Target URL cannot be empty.", "EMPTY_URL"

        try:
            parsed = urlparse(url.strip())
        except Exception:
            return False, "Malformed URL format.", "MALFORMED_URL"

        if parsed.scheme not in ("http", "https"):
            return False, f"Invalid scheme '{parsed.scheme}'. Only http and https protocols are permitted.", "INVALID_SCHEME"

        hostname = parsed.hostname
        if not hostname:
            return False, "URL hostname is missing.", "MISSING_HOSTNAME"

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"

        # --- STRICT DEMO LAB EXCEPTION (Phase 12 / 34) ---
        if is_demo:
            is_valid_demo_host = hostname in settings.DEMO_TARGET_HOSTS
            is_valid_demo_port = port in settings.DEMO_TARGET_PORTS or port in (80, 443)
            is_valid_demo_path = path.startswith(settings.DEMO_TARGET_PATH_PREFIX)

            if is_valid_demo_host and is_valid_demo_port and is_valid_demo_path:
                return True, "Demo sandbox environment authorized under strict ScopeGuard envelope.", "DEMO_SANDBOX_AUTHORIZED"

            if not is_valid_demo_path:
                return False, f"Scope Violation: Demo Lab path '{path}' outside authorized prefix '{settings.DEMO_TARGET_PATH_PREFIX}'.", "OUT_OF_SCOPE_DEMO_PATH"

            if not is_valid_demo_host:
                return False, f"Scope Violation: Demo target host '{hostname}' is not an authorized local demo sandbox host.", "OUT_OF_SCOPE_DEMO_HOST"

        # --- NORMAL TARGET SAFETY INVARIANTS ---
        # 1. Reject explicit IP literals if private/loopback/cloud metadata
        try:
            ip = ipaddress.ip_address(hostname)
            if cls.is_private_or_restricted_ip(str(ip)):
                return False, f"SSRF Security Violation: Direct private or internal IP address '{hostname}' blocked by ScopeGuard.", "SSRF_PRIVATE_IP_BLOCKED"
        except ValueError:
            # Hostname is a domain name -> resolve via DNS to detect DNS rebinding to private IPs
            try:
                addr_info = socket.getaddrinfo(hostname, None)
                for item in addr_info:
                    resolved_ip = item[4][0]
                    if cls.is_private_or_restricted_ip(resolved_ip):
                        return False, f"SSRF Security Violation: Host '{hostname}' resolves to private/internal IP '{resolved_ip}'. Blocked by ScopeGuard.", "SSRF_DNS_REBINDING_BLOCKED"
            except socket.gaierror:
                return False, f"DNS resolution failed for hostname '{hostname}'. Host unreachable or invalid.", "DNS_RESOLUTION_FAILED"

        return True, "Target URL satisfies ScopeGuard safety policies.", "POLICY_PASS"

    @classmethod
    def execute_guarded_request(
        cls,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        is_demo: bool = False,
        timeout: float = 10.0
    ) -> httpx.Response:
        """
        Executes an HTTP request strictly through NetworkGuard boundaries.
        Prevents SSRF redirects, enforces timeouts and headers.
        """
        allowed, reason, rule = cls.evaluate_target_url(url, is_demo=is_demo)
        if not allowed:
            raise PermissionError(f"NetworkGuard blocked request to '{url}': {reason} (Rule: {rule})")

        req_headers = {"User-Agent": "VulnSeal-NetworkGuard/1.0"}
        if headers:
            req_headers.update(headers)

        with httpx.Client(follow_redirects=False, timeout=timeout) as client:
            resp = client.request(method, url, headers=req_headers, data=data)

            # If redirect encountered, guard the redirect destination
            if resp.is_redirect and "location" in resp.headers:
                redirect_url = resp.headers["location"]
                red_allowed, red_reason, red_rule = cls.evaluate_target_url(redirect_url, is_demo=is_demo)
                if not red_allowed:
                    raise PermissionError(f"NetworkGuard blocked redirect to '{redirect_url}': {red_reason} (Rule: {red_rule})")

            return resp

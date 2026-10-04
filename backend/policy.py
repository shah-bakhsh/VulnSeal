"""
VulnSeal ScopeGuard Policy Engine (Python)
SSRF, private network isolation, DNS rebinding, and authorized scan envelope validation.
"""
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Dict, Any, Tuple

class PolicyEngine:
    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return (
                ip.is_private or
                ip.is_loopback or
                ip.is_link_local or
                ip.is_reserved or
                ip.is_multicast or
                ip_str.startswith('0.')
            )
        except ValueError:
            return True

    @classmethod
    def validate_target_url(cls, url: str, is_demo: bool = False) -> Tuple[bool, str]:
        if not url:
            return False, "Target URL cannot be empty."

        try:
            parsed = urlparse(url)
        except Exception:
            return False, "Malformed URL format."

        if parsed.scheme not in ('http', 'https'):
            return False, f"Invalid scheme '{parsed.scheme}'. Only http and https are permitted."

        hostname = parsed.hostname
        if not hostname:
            return False, "URL hostname is missing."

        # Demo target allowlist (only when is_demo=True or explicit demo-target path)
        if is_demo or 'demo-target' in url:
            return True, "Demo sandbox environment authorized under ScopeGuard safe envelope."

        # Check explicit IP literals
        try:
            ip = ipaddress.ip_address(hostname)
            if cls.is_private_ip(str(ip)):
                return False, f"SSRF Security Violation: Direct private network address '{hostname}' blocked by ScopeGuard."
        except ValueError:
            # Domain name - resolve DNS to check for DNS rebinding / private IP resolutions
            try:
                addr_info = socket.getaddrinfo(hostname, None)
                for item in addr_info:
                    resolved_ip = item[4][0]
                    if cls.is_private_ip(resolved_ip):
                        return False, f"SSRF Security Violation: Host '{hostname}' resolves to private/internal IP '{resolved_ip}'. Blocked by ScopeGuard."
            except socket.gaierror:
                return False, f"DNS resolution failed for hostname '{hostname}'."

        return True, "Target URL satisfies ScopeGuard safety policies."

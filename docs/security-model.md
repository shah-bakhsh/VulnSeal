# VulnSeal Security & Threat Model

## Authorization & Ownership

Scanning targets without explicit authorization is strictly prohibited. VulnSeal enforces authorization via:
1. **HTML Meta Tag**: `<meta name="vulnseal-verification" content="<token>" />`
2. **DNS TXT Record**: Verification string published on domain root.
3. **Demo Allowlist**: Dedicated isolated sandboxes owned by the organization.

## SSRF & NetworkGuard Policies

All requests pass through `NetworkGuard`:
- Blocks private IPv4/IPv6 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`).
- Blocks cloud instance metadata endpoints (`169.254.169.254`).
- Restricts requests to allowed origins, hostnames, and rate limits.
- Enforces per-scan request budgets.

## Prompt Injection Defense

All content retrieved from target endpoints (HTML bodies, HTTP headers, repository comments) is classified as untrusted data:
- Target payloads cannot override system policy.
- Target payloads cannot auto-approve patches.
- AI responses are validated strictly against structural JSON schemas before being consumed by agents.

# VulnSeal Architecture Specification

## Overview

VulnSeal closes the security remediation loop: **Find. Fix. Prove.**

```text
AUTHORIZED TARGET
  │
  ▼
ScopeGuard (Authorization & Policy Enforcement)
  │
  ▼
SurfaceMapper (Safe Crawling & Route Mapping)
  │
  ▼
SecurityInspector (Deterministic Security Rules)
  │
  ▼
EvidenceJudge (False-Positive Analysis & Confidence Triage)
  │
  ▼
RootCauseMapper (Runtime-to-Source Mapping)
  │
  ▼
RemediationEngineer (Minimal Safe Patch Candidate)
  │
  ▼
Human Approval Gate (Cryptographic Patch SHA-256 Signature)
  │
  ▼
ShadowFix Digital Twin (Isolated Patch Execution & Build)
  │
  ▼
Security Replay & Regression Tests
  │
  ▼
IndependentVerifier (Consensus Evaluation)
  │
  ▼
Proof of Fix (Immutable Cryptographic Record)
```

## Key Invariants

1. **Never Fake Security**: No mocked findings or synthetic scores. Evidence must be grounded in raw HTTP observations.
2. **Deterministic-First**: Finding truth is established by deterministic inspection tools, not LLM hallucinations.
3. **Defense in Depth**: NetworkGuard enforces strict SSRF protections against internal IPs and cloud metadata addresses.
4. **Separation of Roles**: RemediationEngineer cannot approve or verify its own patch; IndependentVerifier conducts isolated consensus.
5. **No Direct Production Writes**: Patches execute only within isolated ShadowFix digital twins until proven.

"""
VulnSeal Python Backend Data Models & Types
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Literal
import datetime

Severity = Literal['critical', 'high', 'medium', 'low', 'info']

@dataclass
class FindingEvidence:
    id: str
    finding_id: str
    request_method: str
    request_url: str
    request_headers: Dict[str, str]
    response_status: int
    response_status_text: str
    response_headers: Dict[str, str]
    sanitized_excerpt: str
    observation_description: str
    captured_at: str
    sha256_hash: str
    raw_attribute_missing: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class RootCause:
    finding_id: str
    file_path: str
    line_number: int
    code_snippet: str
    symbol: str
    explanation: str
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class PatchCandidate:
    id: str
    finding_id: str
    root_cause: Dict[str, Any]
    affected_file: str
    diff: str
    sha256_hash: str
    explanation: str
    security_effect: str
    risk_assessment: str
    generated_regression_test: str
    verification_plan: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class RemediationApproval:
    id: str
    patch_id: str
    approved_by_email: str
    approved_patch_hash: str
    status: Literal['approved', 'rejected']
    approved_at: str
    rejection_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ProofOfFix:
    id: str
    workspace_id: str
    finding_id: str
    target_url: str
    rule_id: str
    rule_title: str
    severity: Severity
    root_cause_file: str
    root_cause_line: int
    patch_diff: str
    patch_hash: str
    approved_by: str
    approved_at: str
    before_evidence: Dict[str, Any]
    after_evidence: Dict[str, Any]
    security_replay_status: str
    regression_test_status: str
    verifier_verdict: str
    verified_at: str
    proof_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class Finding:
    id: str
    workspace_id: str
    target_id: str
    scan_id: str
    rule_id: str
    rule_name: str
    category: str
    title: str
    description: str
    affected_url: str
    severity: Severity
    confidence: float
    status: str
    evidence: Dict[str, Any]
    created_at: str
    updated_at: str
    root_cause: Optional[Dict[str, Any]] = None
    patch: Optional[Dict[str, Any]] = None
    approval: Optional[Dict[str, Any]] = None
    proof: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class Target:
    id: str
    workspace_id: str
    url: str
    name: str
    is_demo: bool
    status: Literal['unverified', 'authorized', 'revoked', 'expired']
    security_score: Optional[int]
    open_findings_count: int
    verified_fixes_count: int
    created_at: str
    authorized_at: Optional[str] = None
    last_scan_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ScanRun:
    id: str
    workspace_id: str
    target_id: str
    target_url: str
    status: str
    pages_discovered: int
    rules_executed: int = 0
    candidate_findings_count: int = 0
    confirmed_findings_count: int = 0
    dismissed_findings_count: int = 0
    requests_made: int = 0
    started_at: str = ""
    completed_at: Optional[str] = None
    duration_ms: Optional[int] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class AgentEvent:
    id: str
    workspace_id: str
    agent: str
    event_type: Literal['start', 'observe', 'decision', 'complete', 'error', 'block']
    status: Literal['in_progress', 'success', 'warning', 'error']
    message: str
    created_at: str
    scan_id: Optional[str] = None
    finding_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    duration_ms: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class AuditLog:
    id: str
    workspace_id: str
    action: str
    actor: str
    resource_type: str
    resource_id: str
    details: Dict[str, Any]
    timestamp: str
    decision: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

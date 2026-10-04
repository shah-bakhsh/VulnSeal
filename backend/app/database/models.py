"""
VulnSeal SQLAlchemy Database Models
Persists workspaces, targets, scans, findings, patches, proofs, and audit trails.
"""
import uuid
import datetime
import json
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime
from .session import Base

def gen_uuid(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}" if prefix else uuid.uuid4().hex[:16]

def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

class WorkspaceModel(Base):
    __tablename__ = "workspaces"

    id = Column(String(64), primary_key=True, default=lambda: gen_uuid("ws_"))
    name = Column(String(255), nullable=False)
    created_at = Column(String(64), default=utc_now)

class TargetModel(Base):
    __tablename__ = "targets"

    id = Column(String(64), primary_key=True, default=lambda: gen_uuid("tgt_"))
    workspace_id = Column(String(64), nullable=False, default="ws_default_01")
    url = Column(String(1024), nullable=False)
    name = Column(String(255), nullable=False)
    is_demo = Column(Boolean, default=False)
    status = Column(String(32), default="unverified")  # unverified | authorized | revoked | expired
    authorized_at = Column(String(64), nullable=True)
    last_scan_at = Column(String(64), nullable=True)
    security_score = Column(Integer, nullable=True)  # None if not assessed
    open_findings_count = Column(Integer, default=0)
    verified_fixes_count = Column(Integer, default=0)
    created_at = Column(String(64), default=utc_now)

class ChallengeModel(Base):
    __tablename__ = "challenges"

    id = Column(String(64), primary_key=True, default=lambda: gen_uuid("chal_"))
    target_id = Column(String(64), nullable=False)
    challenge_type = Column(String(64), default="meta_tag")
    token = Column(String(128), nullable=False)
    status = Column(String(32), default="pending")  # pending | verified | failed
    created_at = Column(String(64), default=utc_now)
    verified_at = Column(String(64), nullable=True)

class ScanModel(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, default=lambda: gen_uuid("scan_"))
    workspace_id = Column(String(64), nullable=False, default="ws_default_01")
    target_id = Column(String(64), nullable=False)
    target_url = Column(String(1024), nullable=False)
    status = Column(String(32), default="queued")
    pages_discovered = Column(Integer, default=0)
    rules_executed = Column(Integer, default=0)
    candidate_findings_count = Column(Integer, default=0)
    confirmed_findings_count = Column(Integer, default=0)
    dismissed_findings_count = Column(Integer, default=0)
    requests_made = Column(Integer, default=0)
    started_at = Column(String(64), default=utc_now)
    completed_at = Column(String(64), nullable=True)
    duration_ms = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    scope_json = Column(Text, default="{}")

class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True, default=lambda: gen_uuid("fnd_"))
    workspace_id = Column(String(64), nullable=False, default="ws_default_01")
    target_id = Column(String(64), nullable=False)
    scan_id = Column(String(64), nullable=False)
    rule_id = Column(String(128), nullable=False)
    rule_name = Column(String(255), nullable=False)
    category = Column(String(128), default="Security")
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    affected_url = Column(String(1024), nullable=False)
    severity = Column(String(32), default="medium")
    confidence = Column(Float, default=1.0)
    status = Column(String(64), default="confirmed")
    evidence_json = Column(Text, default="{}")
    root_cause_json = Column(Text, nullable=True)
    patch_json = Column(Text, nullable=True)
    approval_json = Column(Text, nullable=True)
    proof_id = Column(String(64), nullable=True)
    created_at = Column(String(64), default=utc_now)
    updated_at = Column(String(64), default=utc_now)

class PatchModel(Base):
    __tablename__ = "patches"

    id = Column(String(64), primary_key=True, default=lambda: gen_uuid("patch_"))
    finding_id = Column(String(64), nullable=False)
    affected_file = Column(String(255), nullable=False)
    diff = Column(Text, nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    explanation = Column(Text, nullable=True)
    security_effect = Column(Text, nullable=True)
    risk_assessment = Column(Text, nullable=True)
    generated_regression_test = Column(Text, nullable=True)
    verification_plan = Column(Text, nullable=True)
    created_at = Column(String(64), default=utc_now)

class ApprovalModel(Base):
    __tablename__ = "approvals"

    id = Column(String(64), primary_key=True, default=lambda: gen_uuid("appr_"))
    patch_id = Column(String(64), nullable=False)
    approved_by_email = Column(String(255), nullable=False)
    approved_patch_hash = Column(String(64), nullable=False)
    status = Column(String(32), default="approved")
    rejection_reason = Column(Text, nullable=True)
    approved_at = Column(String(64), default=utc_now)

class ProofModel(Base):
    __tablename__ = "proofs"

    id = Column(String(64), primary_key=True, default=lambda: gen_uuid("proof_"))
    workspace_id = Column(String(64), nullable=False, default="ws_default_01")
    finding_id = Column(String(64), nullable=False)
    target_url = Column(String(1024), nullable=False)
    rule_id = Column(String(128), nullable=False)
    rule_title = Column(String(255), nullable=False)
    severity = Column(String(32), default="medium")
    root_cause_file = Column(String(255), nullable=False)
    root_cause_line = Column(Integer, default=1)
    patch_diff = Column(Text, nullable=False)
    patch_hash = Column(String(64), nullable=False)
    approved_by = Column(String(255), nullable=False)
    approved_at = Column(String(64), nullable=False)
    before_evidence_json = Column(Text, default="{}")
    after_evidence_json = Column(Text, default="{}")
    security_replay_status = Column(String(32), default="PASS")
    regression_test_status = Column(String(32), default="PASS")
    verifier_verdict = Column(String(32), default="VERIFIED")
    verified_at = Column(String(64), default=utc_now)
    proof_hash = Column(String(64), nullable=False)

class AgentEventModel(Base):
    __tablename__ = "agent_events"

    id = Column(String(64), primary_key=True, default=lambda: gen_uuid("evt_"))
    workspace_id = Column(String(64), nullable=False, default="ws_default_01")
    scan_id = Column(String(64), nullable=True)
    finding_id = Column(String(64), nullable=True)
    agent = Column(String(64), nullable=False)
    event_type = Column(String(32), default="start")
    status = Column(String(32), default="in_progress")
    message = Column(Text, nullable=False)
    metadata_json = Column(Text, default="{}")
    created_at = Column(String(64), default=utc_now)
    duration_ms = Column(Integer, nullable=True)

class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id = Column(String(64), primary_key=True, default=lambda: gen_uuid("audit_"))
    workspace_id = Column(String(64), nullable=False, default="ws_default_01")
    action = Column(String(128), nullable=False)
    actor = Column(String(255), nullable=False)
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(64), nullable=False)
    decision = Column(String(32), nullable=True)
    details_json = Column(Text, default="{}")
    timestamp = Column(String(64), default=utc_now)

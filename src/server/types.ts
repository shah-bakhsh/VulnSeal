export type WorkspaceRole = 'owner' | 'admin' | 'security_engineer' | 'viewer';

export interface Workspace {
  id: string;
  name: string;
  slug: string;
  created_at: string;
}

export type AuthorizationMethod = 'meta_tag' | 'dns_txt' | 'demo_allowlist';

export type TargetStatus = 'unverified' | 'authorized' | 'revoked' | 'expired';

export interface AuthorizationChallenge {
  id: string;
  target_id: string;
  method: AuthorizationMethod;
  token: string;
  expected_value: string;
  status: 'pending' | 'verified' | 'failed' | 'expired';
  created_at: string;
  expires_at: string;
  verified_at?: string;
  failure_reason?: string;
}

export interface Target {
  id: string;
  workspace_id: string;
  url: string;
  name: string;
  is_demo: boolean;
  status: TargetStatus;
  authorized_at?: string;
  last_scan_at?: string;
  security_score: number | null;
  open_findings_count: number;
  verified_fixes_count: number;
  created_at: string;
}

export interface ScanScope {
  target_id: string;
  allowed_origin: string;
  allowed_hosts: string[];
  allowed_paths: string[];
  excluded_paths: string[];
  max_pages: number;
  request_budget: number;
  rate_limit_per_second: number;
  active_testing_permitted: boolean;
}

export type ScanStatus =
  | 'queued'
  | 'authorizing'
  | 'discovering'
  | 'scanning'
  | 'triaging'
  | 'completed'
  | 'completed_with_warnings'
  | 'blocked'
  | 'cancelled'
  | 'failed';

export interface ScanRun {
  id: string;
  workspace_id: string;
  target_id: string;
  target_url: string;
  status: ScanStatus;
  scope: ScanScope;
  pages_discovered: number;
  rules_executed: number;
  candidate_findings_count: number;
  confirmed_findings_count: number;
  dismissed_findings_count: number;
  requests_made: number;
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
  error_message?: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingStatus =
  | 'candidate'
  | 'validating'
  | 'dismissed'
  | 'confirmed'
  | 'root_cause_found'
  | 'remediation_ready'
  | 'waiting_approval'
  | 'approved'
  | 'sandbox_testing'
  | 'patched_in_sandbox'
  | 'verifying'
  | 'verified'
  | 'failed_verification'
  | 'regression_detected';

export interface FindingEvidence {
  id: string;
  finding_id: string;
  request_method: string;
  request_url: string;
  request_headers: Record<string, string>;
  response_status: number;
  response_status_text: string;
  response_headers: Record<string, string>;
  sanitized_excerpt: string;
  observation_description: string;
  raw_attribute_missing?: string;
  captured_at: string;
  sha256_hash: string;
}

export interface Finding {
  id: string;
  workspace_id: string;
  target_id: string;
  scan_id: string;
  rule_id: string;
  rule_name: string;
  category: string;
  title: string;
  description: string;
  affected_url: string;
  severity: Severity;
  confidence: number; // 0.0 - 1.0
  status: FindingStatus;
  evidence: FindingEvidence;
  dismiss_reason?: string;
  remediation_id?: string;
  proof_id?: string;
  created_at: string;
  updated_at: string;
}

export interface RootCause {
  finding_id: string;
  file_path: string;
  line_number: number;
  code_snippet: string;
  symbol: string;
  explanation: string;
  confidence: number;
}

export interface PatchCandidate {
  id: string;
  finding_id: string;
  root_cause: RootCause;
  affected_file: string;
  diff: string;
  sha256_hash: string;
  explanation: string;
  security_effect: string;
  risk_assessment: string;
  generated_regression_test: string;
  verification_plan: string;
  created_at: string;
}

export interface RemediationApproval {
  id: string;
  patch_id: string;
  approved_by_email: string;
  approved_patch_hash: string;
  status: 'approved' | 'rejected';
  rejection_reason?: string;
  approved_at: string;
}

export interface ShadowFixExecutionStep {
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at?: string;
  completed_at?: string;
  detail?: string;
}

export interface ShadowFixRun {
  id: string;
  remediation_id: string;
  finding_id: string;
  workspace_path: string;
  isolation_mode: 'process_sandbox' | 'docker_container';
  status: 'running' | 'completed' | 'failed';
  steps: ShadowFixExecutionStep[];
  security_replay_passed: boolean;
  regression_tests_passed: boolean;
  replay_evidence?: FindingEvidence;
  error?: string;
  started_at: string;
  completed_at?: string;
}

export type VerificationVerdict = 'VERIFIED' | 'FAILED' | 'INCONCLUSIVE' | 'REGRESSION_DETECTED';

export interface VerificationResult {
  id: string;
  finding_id: string;
  patch_id: string;
  shadowfix_id: string;
  verdict: VerificationVerdict;
  verifier_name: 'IndependentVerifier';
  security_replay_match: boolean;
  regression_passed: boolean;
  evidence_complete: boolean;
  patch_hash_verified: boolean;
  reason: string;
  verified_at: string;
}

export interface ProofOfFix {
  id: string;
  workspace_id: string;
  finding_id: string;
  target_url: string;
  rule_id: string;
  rule_title: string;
  severity: Severity;
  root_cause_file: string;
  root_cause_line: number;
  patch_diff: string;
  patch_hash: string;
  approved_by: string;
  approved_at: string;
  before_evidence: {
    attribute_status: string;
    raw_header: string;
    sanitized_excerpt: string;
    reproduction_status: 'REPRODUCED';
  };
  after_evidence: {
    attribute_status: string;
    raw_header: string;
    sanitized_excerpt: string;
    reproduction_status: 'RESOLVED';
  };
  security_replay_status: 'PASS';
  regression_test_status: 'PASS';
  verifier_verdict: 'VERIFIED';
  verified_at: string;
  proof_hash: string;
}

export interface AgentEvent {
  id: string;
  workspace_id: string;
  scan_id?: string;
  finding_id?: string;
  agent:
    | 'ScopeGuard'
    | 'SurfaceMapper'
    | 'SecurityInspector'
    | 'EvidenceJudge'
    | 'RootCauseMapper'
    | 'RemediationEngineer'
    | 'IndependentVerifier'
    | 'PolicyEngine';
  event_type: 'start' | 'observe' | 'decision' | 'complete' | 'error' | 'block';
  status: 'in_progress' | 'success' | 'warning' | 'error';
  message: string;
  metadata?: Record<string, any>;
  created_at: string;
  duration_ms?: number;
}

export interface AuditLog {
  id: string;
  workspace_id: string;
  action: string;
  actor: string;
  resource_type: string;
  resource_id: string;
  decision?: 'ALLOWED' | 'DENIED' | 'APPROVED' | 'REJECTED';
  details: Record<string, any>;
  timestamp: string;
}

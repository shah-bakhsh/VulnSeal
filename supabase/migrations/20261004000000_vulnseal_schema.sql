-- ==============================================================================
-- VULNSEAL DATABASE SCHEMA
-- PostgreSQL + Supabase Multi-Tenant Architecture with Row Level Security (RLS)
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. PROFILES
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE,
  full_name TEXT,
  avatar_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. WORKSPACES
CREATE TABLE IF NOT EXISTS public.workspaces (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. WORKSPACE MEMBERS
CREATE TABLE IF NOT EXISTS public.workspace_members (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'security_engineer', 'viewer')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(workspace_id, user_id)
);

-- 4. TARGETS
CREATE TABLE IF NOT EXISTS public.targets (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  name TEXT NOT NULL,
  is_demo BOOLEAN NOT NULL DEFAULT FALSE,
  status TEXT NOT NULL DEFAULT 'unverified' CHECK (status IN ('unverified', 'authorized', 'revoked', 'expired')),
  authorized_at TIMESTAMPTZ,
  last_scan_at TIMESTAMPTZ,
  security_score INTEGER NOT NULL DEFAULT 100 CHECK (security_score BETWEEN 0 AND 100),
  open_findings_count INTEGER NOT NULL DEFAULT 0,
  verified_fixes_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. AUTHORIZATION CHALLENGES
CREATE TABLE IF NOT EXISTS public.authorization_challenges (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  target_id UUID NOT NULL REFERENCES public.targets(id) ON DELETE CASCADE,
  method TEXT NOT NULL CHECK (method IN ('meta_tag', 'dns_txt', 'demo_allowlist')),
  token TEXT NOT NULL,
  expected_value TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'failed', 'expired')),
  failure_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  verified_at TIMESTAMPTZ
);

-- 6. SCAN RUNS
CREATE TABLE IF NOT EXISTS public.scan_runs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  target_id UUID NOT NULL REFERENCES public.targets(id) ON DELETE CASCADE,
  target_url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'authorizing', 'discovering', 'scanning', 'triaging', 'completed', 'cancelled', 'failed')),
  scope JSONB NOT NULL DEFAULT '{}'::jsonb,
  pages_discovered INTEGER NOT NULL DEFAULT 0,
  rules_executed INTEGER NOT NULL DEFAULT 0,
  candidate_findings_count INTEGER NOT NULL DEFAULT 0,
  confirmed_findings_count INTEGER NOT NULL DEFAULT 0,
  dismissed_findings_count INTEGER NOT NULL DEFAULT 0,
  requests_made INTEGER NOT NULL DEFAULT 0,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  duration_ms INTEGER,
  error_message TEXT
);

-- 7. FINDINGS
CREATE TABLE IF NOT EXISTS public.findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  target_id UUID NOT NULL REFERENCES public.targets(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES public.scan_runs(id) ON DELETE SET NULL,
  rule_id TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  affected_url TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  confidence NUMERIC(3,2) NOT NULL CHECK (confidence BETWEEN 0.0 AND 1.0),
  status TEXT NOT NULL DEFAULT 'candidate',
  evidence JSONB NOT NULL,
  dismiss_reason TEXT,
  remediation_id UUID,
  proof_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 8. ROOT CAUSE MAPPINGS
CREATE TABLE IF NOT EXISTS public.root_cause_mappings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  finding_id UUID NOT NULL REFERENCES public.findings(id) ON DELETE CASCADE,
  file_path TEXT NOT NULL,
  line_number INTEGER NOT NULL,
  symbol TEXT NOT NULL,
  code_snippet TEXT NOT NULL,
  explanation TEXT NOT NULL,
  confidence NUMERIC(3,2) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 9. PATCH CANDIDATES
CREATE TABLE IF NOT EXISTS public.patch_candidates (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  finding_id UUID NOT NULL REFERENCES public.findings(id) ON DELETE CASCADE,
  affected_file TEXT NOT NULL,
  diff TEXT NOT NULL,
  sha256_hash TEXT NOT NULL,
  explanation TEXT NOT NULL,
  security_effect TEXT NOT NULL,
  risk_assessment TEXT NOT NULL,
  generated_regression_test TEXT NOT NULL,
  verification_plan TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 10. APPROVALS
CREATE TABLE IF NOT EXISTS public.remediation_approvals (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  patch_id UUID NOT NULL REFERENCES public.patch_candidates(id) ON DELETE CASCADE,
  approved_by_email TEXT NOT NULL,
  approved_patch_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('approved', 'rejected')),
  rejection_reason TEXT,
  approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 11. SHADOWFIX RUNS
CREATE TABLE IF NOT EXISTS public.shadowfix_runs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  remediation_id UUID NOT NULL REFERENCES public.patch_candidates(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES public.findings(id) ON DELETE CASCADE,
  workspace_path TEXT NOT NULL,
  isolation_mode TEXT NOT NULL DEFAULT 'process_sandbox',
  status TEXT NOT NULL DEFAULT 'running',
  steps JSONB NOT NULL DEFAULT '[]'::jsonb,
  security_replay_passed BOOLEAN NOT NULL DEFAULT FALSE,
  regression_tests_passed BOOLEAN NOT NULL DEFAULT FALSE,
  error TEXT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

-- 12. PROOFS OF FIX
CREATE TABLE IF NOT EXISTS public.proofs_of_fix (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES public.findings(id) ON DELETE CASCADE,
  target_url TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_title TEXT NOT NULL,
  severity TEXT NOT NULL,
  root_cause_file TEXT NOT NULL,
  root_cause_line INTEGER NOT NULL,
  patch_diff TEXT NOT NULL,
  patch_hash TEXT NOT NULL,
  approved_by TEXT NOT NULL,
  approved_at TIMESTAMPTZ NOT NULL,
  before_evidence JSONB NOT NULL,
  after_evidence JSONB NOT NULL,
  security_replay_status TEXT NOT NULL DEFAULT 'PASS',
  regression_test_status TEXT NOT NULL DEFAULT 'PASS',
  verifier_verdict TEXT NOT NULL DEFAULT 'VERIFIED',
  proof_hash TEXT NOT NULL,
  verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 13. AGENT EVENTS
CREATE TABLE IF NOT EXISTS public.agent_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES public.scan_runs(id) ON DELETE SET NULL,
  finding_id UUID REFERENCES public.findings(id) ON DELETE SET NULL,
  agent TEXT NOT NULL,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL,
  message TEXT NOT NULL,
  metadata JSONB,
  duration_ms INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 14. AUDIT LOGS
CREATE TABLE IF NOT EXISTS public.audit_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  workspace_id UUID NOT NULL REFERENCES public.workspaces(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  decision TEXT CHECK (decision IN ('ALLOWED', 'DENIED', 'APPROVED', 'REJECTED')),
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==============================================================================
-- INDEXES
-- ==============================================================================
CREATE INDEX IF NOT EXISTS idx_targets_workspace ON public.targets(workspace_id);
CREATE INDEX IF NOT EXISTS idx_scans_workspace ON public.scan_runs(workspace_id);
CREATE INDEX IF NOT EXISTS idx_findings_workspace ON public.findings(workspace_id);
CREATE INDEX IF NOT EXISTS idx_findings_target ON public.findings(target_id);
CREATE INDEX IF NOT EXISTS idx_proofs_workspace ON public.proofs_of_fix(workspace_id);
CREATE INDEX IF NOT EXISTS idx_events_workspace ON public.agent_events(workspace_id);
CREATE INDEX IF NOT EXISTS idx_audit_workspace ON public.audit_logs(workspace_id);

-- ==============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- Ensures Workspace A cannot access Workspace B
-- ==============================================================================
ALTER TABLE public.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspace_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.proofs_of_fix ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY workspace_member_access ON public.workspaces
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM public.workspace_members
      WHERE workspace_members.workspace_id = workspaces.id
      AND workspace_members.user_id = auth.uid()
    )
  );

CREATE POLICY target_tenant_isolation ON public.targets
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM public.workspace_members
      WHERE workspace_members.workspace_id = targets.workspace_id
      AND workspace_members.user_id = auth.uid()
    )
  );

CREATE POLICY scan_tenant_isolation ON public.scan_runs
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM public.workspace_members
      WHERE workspace_members.workspace_id = scan_runs.workspace_id
      AND workspace_members.user_id = auth.uid()
    )
  );

CREATE POLICY finding_tenant_isolation ON public.findings
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM public.workspace_members
      WHERE workspace_members.workspace_id = findings.workspace_id
      AND workspace_members.user_id = auth.uid()
    )
  );

CREATE POLICY proof_tenant_isolation ON public.proofs_of_fix
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM public.workspace_members
      WHERE workspace_members.workspace_id = proofs_of_fix.workspace_id
      AND workspace_members.user_id = auth.uid()
    )
  );

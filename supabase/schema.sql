-- ============================================================
-- VulnSeal Enterprise Security Platform — Supabase Schema
-- Run this script in the Supabase SQL Editor:
-- Dashboard -> Your Project -> SQL Editor -> New Query
-- ============================================================

-- 1. Workspaces Table
CREATE TABLE IF NOT EXISTS public.workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Targets Table
CREATE TABLE IF NOT EXISTS public.targets (
    id TEXT PRIMARY KEY,
    workspace_id TEXT REFERENCES public.workspaces(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    name TEXT NOT NULL,
    is_demo BOOLEAN DEFAULT FALSE,
    status TEXT NOT NULL CHECK (status IN ('unverified', 'pending_challenge', 'authorized', 'revoked')),
    authorized_at TIMESTAMPTZ,
    security_score INTEGER DEFAULT 100,
    open_findings_count INTEGER DEFAULT 0,
    verified_fixes_count INTEGER DEFAULT 0,
    last_scan_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Authorization Challenges Table
CREATE TABLE IF NOT EXISTS public.authorization_challenges (
    id TEXT PRIMARY KEY,
    target_id TEXT REFERENCES public.targets(id) ON DELETE CASCADE,
    method TEXT NOT NULL CHECK (method IN ('meta_tag', 'dns_txt', 'demo_allowlist')),
    token TEXT NOT NULL,
    expected_value TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'verified', 'expired')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ
);

-- 4. Scans Table
CREATE TABLE IF NOT EXISTS public.scans (
    id TEXT PRIMARY KEY,
    workspace_id TEXT REFERENCES public.workspaces(id) ON DELETE CASCADE,
    target_id TEXT REFERENCES public.targets(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'crawling', 'inspecting', 'verifying', 'completed', 'failed')),
    start_time TIMESTAMPTZ DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    endpoints_crawled JSONB DEFAULT '[]'::jsonb,
    open_findings_count INTEGER DEFAULT 0,
    findings_detected JSONB DEFAULT '[]'::jsonb,
    agent_logs JSONB DEFAULT '[]'::jsonb
);

-- 5. Findings Table
CREATE TABLE IF NOT EXISTS public.findings (
    id TEXT PRIMARY KEY,
    workspace_id TEXT REFERENCES public.workspaces(id) ON DELETE CASCADE,
    target_id TEXT REFERENCES public.targets(id) ON DELETE CASCADE,
    scan_id TEXT REFERENCES public.scans(id) ON DELETE SET NULL,
    target_url TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    rule_id TEXT NOT NULL,
    rule_title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    description TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('detected', 'root_cause_mapped', 'patch_ready', 'shadowfix_verified', 'approved', 'dismissed')),
    evidence JSONB,
    remediation JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. Proof of Fixes Table
CREATE TABLE IF NOT EXISTS public.proof_of_fixes (
    id TEXT PRIMARY KEY,
    workspace_id TEXT REFERENCES public.workspaces(id) ON DELETE CASCADE,
    target_id TEXT REFERENCES public.targets(id) ON DELETE CASCADE,
    finding_id TEXT REFERENCES public.findings(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    rule_title TEXT NOT NULL,
    target_url TEXT NOT NULL,
    verified_at TIMESTAMPTZ DEFAULT NOW(),
    verifier TEXT NOT NULL,
    original_status TEXT NOT NULL,
    patched_status TEXT NOT NULL,
    patch_hash TEXT NOT NULL,
    verification_gates JSONB NOT NULL,
    proof_hash TEXT NOT NULL UNIQUE
);

-- 7. Audit Logs Table
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id TEXT PRIMARY KEY,
    workspace_id TEXT REFERENCES public.workspaces(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('ALLOWED', 'DENIED', 'REQUIRES_CONFIRMATION')),
    details JSONB
);

-- Enable Row Level Security (RLS) on all tables
ALTER TABLE public.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authorization_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.proof_of_fixes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- Allow full access for anon/authenticated API keys
CREATE POLICY "Allow public read-write for workspaces" ON public.workspaces FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for targets" ON public.targets FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for challenges" ON public.authorization_challenges FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for scans" ON public.scans FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for findings" ON public.findings FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for proof_of_fixes" ON public.proof_of_fixes FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for audit_logs" ON public.audit_logs FOR ALL USING (true) WITH CHECK (true);

-- Seed Default Workspace & Demo Target
INSERT INTO public.workspaces (id, name, created_at)
VALUES ('ws_default_01', 'Default Enterprise Security Workspace', NOW())
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.targets (id, workspace_id, url, name, is_demo, status, authorized_at, security_score, open_findings_count, verified_fixes_count, created_at)
VALUES (
    'target_demo_01',
    'ws_default_01',
    'http://localhost:3000/demo/target',
    'Acme In-Memory Demo API (Isolated)',
    TRUE,
    'authorized',
    NOW(),
    68,
    3,
    1,
    NOW()
)
ON CONFLICT (id) DO NOTHING;

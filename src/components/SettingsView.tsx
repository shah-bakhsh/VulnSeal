import React, { useState, useEffect } from 'react';
import {
  Database,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  RefreshCw,
  ExternalLink,
  Shield,
  Cpu,
  Key,
  Download,
} from 'lucide-react';
import { fetchSupabaseStatus, fetchEngineStatus } from '../lib/api';
import { VulnSealLogo, VulnSealBrand } from './brand';

export const SettingsView: React.FC = () => {
  const [copiedSql, setCopiedSql] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [supabaseStatus, setSupabaseStatus] = useState<{
    connected: boolean;
    configured: boolean;
    url?: string;
    message: string;
  } | null>(null);

  const [engineStatus, setEngineStatus] = useState<{
    hasGroq: boolean;
    hasGemini: boolean;
    activeProvider: string;
    model: string;
    offlineFallbackReady: boolean;
  } | null>(null);

  const sqlSchemaQuery = `-- ============================================================
-- VulnSeal Supabase PostgreSQL Schema
-- Paste and Run in Supabase SQL Editor:
-- https://supabase.com/dashboard/project/_/sql
-- ============================================================

CREATE TABLE IF NOT EXISTS public.workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

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

-- Allow public read-write policies
CREATE POLICY "Allow public read-write for workspaces" ON public.workspaces FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for targets" ON public.targets FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for challenges" ON public.authorization_challenges FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for scans" ON public.scans FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for findings" ON public.findings FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for proof_of_fixes" ON public.proof_of_fixes FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow public read-write for audit_logs" ON public.audit_logs FOR ALL USING (true) WITH CHECK (true);

-- Seed Default Workspace
INSERT INTO public.workspaces (id, name, created_at)
VALUES ('ws_default_01', 'Default Enterprise Security Workspace', NOW())
ON CONFLICT (id) DO NOTHING;`;

  const checkStatus = async () => {
    setIsTesting(true);
    try {
      const [supa, engine] = await Promise.all([
        fetchSupabaseStatus(),
        fetchEngineStatus(),
      ]);
      setSupabaseStatus(supa);
      setEngineStatus(engine);
    } catch {
      // Ignored
    } finally {
      setIsTesting(false);
    }
  };

  useEffect(() => {
    checkStatus();
  }, []);

  const handleCopySql = () => {
    navigator.clipboard.writeText(sqlSchemaQuery);
    setCopiedSql(true);
    setTimeout(() => setCopiedSql(false), 2500);
  };

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
          System & Database Settings
        </h2>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
          Manage your cloud database connection, SQL schemas, and AI inference engines.
        </p>
      </div>

      {/* Supabase Integration Card */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-2xs">
        <div className="p-5 border-b border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 flex items-center justify-center text-emerald-600 dark:text-emerald-400 shrink-0">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                  Supabase PostgreSQL Connection
                </h3>
                {supabaseStatus?.connected ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300">
                    <CheckCircle2 className="w-3 h-3" />
                    Connected & Active
                  </span>
                ) : supabaseStatus?.configured ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300">
                    <AlertCircle className="w-3 h-3" />
                    Schema Missing
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300">
                    Local Storage Active
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {supabaseStatus?.message || 'Using local disk storage (.vulnseal-db.json)'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={checkStatus}
              disabled={isTesting}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isTesting ? 'animate-spin' : ''}`} />
              <span>Test Connection</span>
            </button>
            <a
              href="https://supabase.com/dashboard"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-xs font-semibold text-white transition-colors"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Supabase Dashboard</span>
            </a>
          </div>
        </div>

        {/* Setup Instructions */}
        <div className="p-5 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-2">
              <span className="text-xs font-semibold text-slate-900 dark:text-white flex items-center gap-1.5">
                <Key className="w-3.5 h-3.5 text-blue-500" />
                Step 1: Environment Variables
              </span>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
                Add your Supabase credentials into your environment or Secrets configuration:
              </p>
              <div className="p-2.5 rounded bg-slate-900 text-slate-100 font-mono text-[10.5px] leading-relaxed">
                <code>SUPABASE_URL="https://your-project-id.supabase.co"<br />
                SUPABASE_ANON_KEY="eyJhbGciOiJIUzI1Ni..."</code>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-2">
              <span className="text-xs font-semibold text-slate-900 dark:text-white flex items-center gap-1.5">
                <Database className="w-3.5 h-3.5 text-emerald-500" />
                Step 2: Run Schema in SQL Editor
              </span>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
                Copy the SQL schema script below, navigate to your <strong>Supabase Dashboard &gt; SQL Editor</strong>, and click <strong>Run</strong>.
              </p>
              <button
                onClick={handleCopySql}
                className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded bg-emerald-600 hover:bg-emerald-700 text-white font-medium text-xs transition-colors"
              >
                {copiedSql ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-200" />
                    <span>SQL Copied to Clipboard!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy Full SQL Schema Script</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Collapsible SQL preview */}
          <div className="border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden">
            <div className="bg-slate-100 dark:bg-slate-800/80 px-4 py-2 flex items-center justify-between">
              <span className="text-xs font-mono font-medium text-slate-700 dark:text-slate-300">
                supabase/schema.sql (PostgreSQL)
              </span>
              <button
                onClick={handleCopySql}
                className="inline-flex items-center gap-1 text-[11px] text-blue-600 dark:text-blue-400 hover:underline"
              >
                {copiedSql ? 'Copied!' : 'Copy Code'}
              </button>
            </div>
            <pre className="p-4 text-[11px] font-mono leading-relaxed bg-slate-900 text-slate-200 overflow-x-auto max-h-64">
              {sqlSchemaQuery}
            </pre>
          </div>
        </div>
      </div>

      {/* AI Inference Engine Status Card */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4 shadow-2xs">
        <div className="flex items-center gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
          <div className="w-10 h-10 rounded-lg bg-blue-50 dark:bg-blue-950/60 border border-blue-200 dark:border-blue-800 flex items-center justify-center text-blue-600 dark:text-blue-400 shrink-0">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
              AI Inference Tier Hierarchy
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Active Provider: <strong className="text-slate-900 dark:text-white">{engineStatus?.activeProvider}</strong> ({engineStatus?.model})
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className={`p-3.5 rounded-lg border text-xs space-y-1.5 ${engineStatus?.hasGroq ? 'border-emerald-200 dark:border-emerald-800 bg-emerald-50/50 dark:bg-emerald-950/30' : 'border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/30'}`}>
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-900 dark:text-white">1. Groq Cloud</span>
              <span className={`w-2 h-2 rounded-full ${engineStatus?.hasGroq ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'}`} />
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Ultra-fast Llama 3.3 70B reasoning for EvidenceJudge &amp; Patch Synthesis.
            </p>
            <span className="text-[10px] font-mono text-slate-400">
              Status: {engineStatus?.hasGroq ? 'Configured & Active' : 'Not Provided'}
            </span>
          </div>

          <div className={`p-3.5 rounded-lg border text-xs space-y-1.5 ${engineStatus?.hasGemini ? 'border-emerald-200 dark:border-emerald-800 bg-emerald-50/50 dark:bg-emerald-950/30' : 'border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/30'}`}>
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-900 dark:text-white">2. Google Gemini</span>
              <span className={`w-2 h-2 rounded-full ${engineStatus?.hasGemini ? 'bg-emerald-500' : 'bg-slate-400'}`} />
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Gemini 3.8 Flash automated fallback model for deep security analysis.
            </p>
            <span className="text-[10px] font-mono text-slate-400">
              Status: {engineStatus?.hasGemini ? 'Configured' : 'Not Provided'}
            </span>
          </div>

          <div className="p-3.5 rounded-lg border border-blue-200 dark:border-blue-800 bg-blue-50/50 dark:bg-blue-950/30 text-xs space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-slate-900 dark:text-white">3. Offline Defense</span>
              <span className="w-2 h-2 rounded-full bg-blue-500" />
            </div>
            <p className="text-[11px] text-slate-500 dark:text-slate-400">
              Deterministic AST &amp; header repair engine that operates 100% offline.
            </p>
            <span className="text-[10px] font-mono text-blue-600 dark:text-blue-400">
              Status: Always Active
            </span>
          </div>
        </div>
      </div>

      {/* Official Brand Identity & Design System */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4 shadow-2xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-slate-100 dark:border-slate-800">
          <div className="flex items-center gap-3.5">
            <VulnSealLogo size="lg" />
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900 dark:text-white">
                  Vuln<span className="text-blue-600 dark:text-blue-400">Seal</span>
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-50 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-800">
                  OFFICIAL BRAND
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-medium">
                Find. Fix. Prove. &mdash; Autonomous cybersecurity remediation with verified proof.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <a
              href="/brand/vulnseal-logo.svg"
              download="vulnseal-logo.svg"
              className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/80 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors shadow-2xs"
            >
              <Download className="w-3.5 h-3.5" />
              <span>SVG Vector</span>
            </a>
            <a
              href="/brand/vulnseal-logo.png"
              download="vulnseal-logo.png"
              className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/80 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors shadow-2xs"
            >
              <Download className="w-3.5 h-3.5" />
              <span>PNG (512px)</span>
            </a>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="p-3 rounded-lg border border-slate-100 dark:border-slate-800/60 bg-slate-50/50 dark:bg-slate-950/30">
            <div className="text-[10px] font-mono text-slate-400 uppercase">Primary Blue</div>
            <div className="flex items-center gap-2 mt-1">
              <span className="w-4 h-4 rounded-full bg-[#2563EB] shadow-xs shrink-0" />
              <span className="font-mono text-slate-800 dark:text-slate-200 font-semibold">#2563EB</span>
            </div>
          </div>
          <div className="p-3 rounded-lg border border-slate-100 dark:border-slate-800/60 bg-slate-50/50 dark:bg-slate-950/30">
            <div className="text-[10px] font-mono text-slate-400 uppercase">Deep Blue</div>
            <div className="flex items-center gap-2 mt-1">
              <span className="w-4 h-4 rounded-full bg-[#1D4ED8] shadow-xs shrink-0" />
              <span className="font-mono text-slate-800 dark:text-slate-200 font-semibold">#1D4ED8</span>
            </div>
          </div>
          <div className="p-3 rounded-lg border border-slate-100 dark:border-slate-800/60 bg-slate-50/50 dark:bg-slate-950/30">
            <div className="text-[10px] font-mono text-slate-400 uppercase">Electric Cyan</div>
            <div className="flex items-center gap-2 mt-1">
              <span className="w-4 h-4 rounded-full bg-[#38BDF8] shadow-xs shrink-0" />
              <span className="font-mono text-slate-800 dark:text-slate-200 font-semibold">#38BDF8</span>
            </div>
          </div>
          <div className="p-3 rounded-lg border border-slate-100 dark:border-slate-800/60 bg-slate-50/50 dark:bg-slate-950/30">
            <div className="text-[10px] font-mono text-slate-400 uppercase">Dark Charcoal</div>
            <div className="flex items-center gap-2 mt-1">
              <span className="w-4 h-4 rounded-full bg-[#0F172A] shadow-xs shrink-0" />
              <span className="font-mono text-slate-800 dark:text-slate-200 font-semibold">#0F172A</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

import React from 'react';
import type { Target, ScanRun, Finding, ProofOfFix, AgentEvent } from '../types/client';
import { SeverityBadge } from './SeverityBadge';
import { StatusBadge } from './StatusBadge';
import {
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Wrench,
  Shield,
  Plus,
  Terminal,
  Activity,
  ArrowUpRight,
} from 'lucide-react';
import { NavItem } from './Navigation';

interface OverviewViewProps {
  targets: Target[];
  scans: ScanRun[];
  findings: Finding[];
  proofs: ProofOfFix[];
  agentEvents: AgentEvent[];
  onNavigate: (tab: NavItem) => void;
  onStartDemoScan: () => Promise<void>;
  isScanning: boolean;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  targets,
  scans,
  findings,
  proofs,
  agentEvents,
  onNavigate,
  onStartDemoScan,
  isScanning,
}) => {
  // Compute overall security score across assessed targets
  const assessedTargets = targets.filter((t) => t.security_score !== null && t.security_score !== undefined);
  const avgScore =
    assessedTargets.length > 0
      ? Math.round(assessedTargets.reduce((acc, t) => acc + (t.security_score || 0), 0) / assessedTargets.length)
      : null;

  const openFindings = findings.filter((f) => f.status !== 'verified' && f.status !== 'dismissed');
  const awaitingApproval = findings.filter((f) => f.status === 'waiting_approval');
  const highOrCritical = openFindings.filter((f) => f.severity === 'critical' || f.severity === 'high');

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Page H1 Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-100 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
            Overview
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Security posture and verified remediation across your authorized applications.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => onNavigate('demo')}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors shadow-2xs"
          >
            <Terminal className="w-3.5 h-3.5 text-amber-500" />
            <span>Open Demo Lab</span>
          </button>

          <button
            onClick={() => onNavigate('targets')}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Target</span>
          </button>
        </div>
      </div>

      {/* Core FIND → FIX → PROVE Workflow Banner */}
      <div className="p-4 rounded-xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-2xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-4 sm:gap-6 text-xs">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-blue-600 dark:bg-blue-400" />
              <span className="font-bold text-slate-900 dark:text-white tracking-wide uppercase text-[11px] font-mono">
                Remediation Loop
              </span>
            </div>

            <div
              onClick={() => onNavigate('findings')}
              className="flex items-center gap-1.5 cursor-pointer group"
              title="Click to view findings"
            >
              <span className="font-mono font-bold text-sm text-slate-900 dark:text-white group-hover:text-blue-600 transition-colors">
                {openFindings.length}
              </span>
              <span className="text-slate-600 dark:text-slate-400">FIND (Confirmed)</span>
            </div>

            <span className="text-slate-300 dark:text-slate-700 hidden sm:inline font-bold">→</span>

            <div
              onClick={() => onNavigate('remediation')}
              className="flex items-center gap-1.5 cursor-pointer group"
              title="Click to review pending fixes"
            >
              <span className={`font-mono font-bold text-sm ${awaitingApproval.length > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-slate-900 dark:text-white'} group-hover:text-amber-600 transition-colors`}>
                {awaitingApproval.length}
              </span>
              <span className="text-slate-600 dark:text-slate-400">FIX (Awaiting Approval)</span>
            </div>

            <span className="text-slate-300 dark:text-slate-700 hidden sm:inline font-bold">→</span>

            <div
              onClick={() => onNavigate('proofs')}
              className="flex items-center gap-1.5 cursor-pointer group"
              title="Click to view Proof Center"
            >
              <span className="font-mono font-bold text-sm text-emerald-600 dark:text-emerald-400 group-hover:underline">
                {proofs.length}
              </span>
              <span className="text-slate-600 dark:text-slate-400">PROVE (Verified)</span>
            </div>
          </div>

          <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 flex items-center gap-1.5 shrink-0">
            <Shield className="w-3.5 h-3.5 text-blue-500" />
            <span>Deterministic Verification Engine Active</span>
          </div>
        </div>
      </div>

      {/* Metric Cards Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        {/* Metric 1: Security Score */}
        <div
          onClick={() => onNavigate('targets')}
          className="p-4 rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-2xs space-y-1 cursor-pointer hover:border-slate-300 dark:hover:border-slate-700 transition-colors group"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Security Score</span>
            <Shield className="w-3.5 h-3.5 text-blue-500" />
          </div>
          <div className="flex items-baseline gap-1.5">
            {avgScore !== null ? (
              <>
                <span className="text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-white">
                  {avgScore}
                </span>
                <span className="text-xs text-slate-400">/ 100</span>
              </>
            ) : (
              <span className="text-2xl font-bold font-mono text-slate-400 dark:text-slate-500">
                —
              </span>
            )}
          </div>
          <p className="text-[11px] text-slate-400 truncate">
            {avgScore !== null
              ? avgScore >= 90
                ? 'Strong security posture'
                : 'Action required'
              : 'Not assessed · Run scan to calculate'}
          </p>
        </div>

        {/* Metric 2: Open Findings */}
        <div
          onClick={() => onNavigate('findings')}
          className="p-4 rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-2xs space-y-1 cursor-pointer hover:border-slate-300 dark:hover:border-slate-700 transition-colors group"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Open Findings</span>
            <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-white">
              {openFindings.length}
            </span>
          </div>
          <p className="text-[11px] text-slate-400">
            {highOrCritical.length > 0 ? `${highOrCritical.length} high priority` : '0 high priority'}
          </p>
        </div>

        {/* Metric 3: Fixes Awaiting Approval */}
        <div
          onClick={() => onNavigate('remediation')}
          className="p-4 rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-2xs space-y-1 cursor-pointer hover:border-slate-300 dark:hover:border-slate-700 transition-colors group"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Awaiting Approval</span>
            <Wrench className="w-3.5 h-3.5 text-blue-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-2xl font-bold font-mono tabular-nums ${
              awaitingApproval.length > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-slate-900 dark:text-white'
            }`}>
              {awaitingApproval.length}
            </span>
          </div>
          <p className="text-[11px] text-slate-400">
            {awaitingApproval.length > 0 ? 'Human sign-off required' : 'No pending patches'}
          </p>
        </div>

        {/* Metric 4: Verified Fixes */}
        <div
          onClick={() => onNavigate('proofs')}
          className="p-4 rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900/80 shadow-2xs space-y-1 cursor-pointer hover:border-slate-300 dark:hover:border-slate-700 transition-colors group"
        >
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Verified Fixes</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono tabular-nums text-emerald-600 dark:text-emerald-400">
              {proofs.length}
            </span>
          </div>
          <p className="text-[11px] text-slate-400">
            {proofs.length > 0 ? 'Replay & regression passed' : 'Proofs appear after verification'}
          </p>
        </div>
      </div>

      {/* Needs Your Attention (Actionable alerts) */}
      {awaitingApproval.length > 0 && (
        <div className="rounded-xl border border-amber-200/80 dark:border-amber-900/50 bg-amber-50/40 dark:bg-amber-950/20 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
              <h3 className="text-xs font-bold text-amber-950 dark:text-amber-200">
                Action Required: Human Patch Approval
              </h3>
            </div>
            <button
              onClick={() => onNavigate('remediation')}
              className="text-xs text-amber-800 dark:text-amber-300 font-semibold hover:underline"
            >
              Review all ({awaitingApproval.length}) →
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {awaitingApproval.slice(0, 2).map((f) => (
              <div
                key={f.id}
                className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-amber-200/60 dark:border-amber-900/40 flex items-center justify-between gap-3 text-xs shadow-2xs"
              >
                <div className="min-w-0">
                  <div className="font-semibold text-slate-900 dark:text-white truncate">
                    {f.title}
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono truncate mt-0.5">
                    Patch ready · {f.affected_url}
                  </div>
                </div>
                <button
                  onClick={() => onNavigate('remediation')}
                  className="px-2.5 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-semibold text-xs shrink-0 transition-colors shadow-2xs"
                >
                  Review Patch
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Two Column Layout: Active Findings & Verified Repairs */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 7 Cols: Active Findings */}
        <div className="lg:col-span-7 rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900/80 p-5 space-y-4 shadow-2xs">
          <div className="flex items-center justify-between pb-2 border-b border-slate-100 dark:border-slate-800">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                Active Findings
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Grounded in deterministic HTTP evidence
              </p>
            </div>
            {findings.length > 0 && (
              <button
                onClick={() => onNavigate('findings')}
                className="text-xs text-blue-600 dark:text-blue-400 font-medium hover:underline flex items-center gap-1"
              >
                <span>View all ({findings.length})</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            )}
          </div>

          <div className="space-y-2">
            {findings.slice(0, 4).map((f) => (
              <div
                key={f.id}
                onClick={() => onNavigate('findings')}
                className="p-3 rounded-lg border border-slate-100 dark:border-slate-800/80 hover:bg-slate-50/60 dark:hover:bg-slate-800/40 transition-colors cursor-pointer flex items-center justify-between gap-3"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <SeverityBadge severity={f.severity} />
                  <div className="min-w-0">
                    <div className="font-semibold text-xs text-slate-900 dark:text-white truncate">
                      {f.title}
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 truncate mt-0.5">
                      {f.rule_id} · {f.affected_url}
                    </div>
                  </div>
                </div>

                <div className="shrink-0 flex items-center gap-2">
                  <StatusBadge status={f.status} />
                  <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                </div>
              </div>
            ))}

            {findings.length === 0 && (
              <div className="py-8 text-center text-xs text-slate-500 space-y-3">
                <div className="w-10 h-10 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center mx-auto text-slate-400">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div>
                  <p className="font-semibold text-slate-800 dark:text-slate-200">No confirmed findings yet</p>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Run a security scan on an authorized target to inspect for weaknesses.
                  </p>
                </div>
                <button
                  onClick={() => onNavigate(targets.length > 0 ? 'scans' : 'targets')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors shadow-2xs"
                >
                  <span>{targets.length > 0 ? 'Go to Scans' : 'Add Target'}</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Right 5 Cols: Verified Proofs & Activity */}
        <div className="lg:col-span-5 space-y-6">
          {/* Verified Proofs Card */}
          <div className="rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900/80 p-5 space-y-4 shadow-2xs">
            <div className="flex items-center justify-between pb-2 border-b border-slate-100 dark:border-slate-800">
              <div>
                <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                  Verified Repairs
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Evidence-backed Proof of Fix certificates
                </p>
              </div>
              {proofs.length > 0 && (
                <button
                  onClick={() => onNavigate('proofs')}
                  className="text-xs text-emerald-600 dark:text-emerald-400 font-medium hover:underline flex items-center gap-1"
                >
                  <span>View all ({proofs.length})</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              )}
            </div>

            <div className="space-y-2">
              {proofs.slice(0, 3).map((p) => (
                <div
                  key={p.id}
                  onClick={() => onNavigate('proofs')}
                  className="p-3 rounded-lg border border-emerald-100 dark:border-emerald-950/60 bg-emerald-50/20 dark:bg-emerald-950/10 hover:bg-emerald-50/40 transition-colors cursor-pointer space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-slate-900 dark:text-white truncate">
                      {p.rule_title}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-900/80 text-emerald-800 dark:text-emerald-200 font-bold">
                      VERIFIED
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between">
                    <span>Replay: PASS · 4/4 Tests</span>
                    <span className="text-emerald-600 dark:text-emerald-400">{p.proof_hash.slice(0, 10)}...</span>
                  </div>
                </div>
              ))}

              {proofs.length === 0 && (
                <div className="py-6 text-center text-xs text-slate-500 space-y-2">
                  <p className="font-medium text-slate-700 dark:text-slate-300">No verified fixes yet</p>
                  <p className="text-[11px] text-slate-400">
                    Verified repairs will appear after a patch passes security replay and regression verification.
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Recent Agent Activity feed snippet */}
          <div className="rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900/80 p-5 space-y-3 shadow-2xs">
            <div className="flex items-center justify-between pb-1 border-b border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-blue-500" />
                <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
                  Agent Activity
                </h3>
              </div>
              <button
                onClick={() => onNavigate('agents')}
                className="text-xs text-blue-600 dark:text-blue-400 font-medium hover:underline flex items-center gap-1"
              >
                <span>Timeline</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            <div className="space-y-2">
              {agentEvents.slice(0, 3).map((e) => (
                <div key={e.id} className="text-xs text-slate-600 dark:text-slate-300 flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1.5 shrink-0" />
                  <div className="min-w-0">
                    <span className="font-semibold text-slate-800 dark:text-slate-200">{e.agent}: </span>
                    <span className="text-slate-500 dark:text-slate-400 truncate block">{e.message}</span>
                  </div>
                </div>
              ))}

              {agentEvents.length === 0 && (
                <div className="py-4 text-center text-xs text-slate-400">
                  No recent agent events.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

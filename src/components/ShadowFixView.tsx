import React from 'react';
import type { Finding, ShadowFixRun } from '../types/client';
import { StatusBadge } from './StatusBadge';
import { Cpu, CheckCircle2, Clock, XCircle, ShieldCheck, ArrowRight, Info } from 'lucide-react';
import { NavItem } from './Navigation';

interface ShadowFixViewProps {
  findings: Finding[];
  onNavigate: (tab: NavItem) => void;
  onRunShadowFix: (patchId: string) => Promise<void>;
  isActionRunning: boolean;
}

export const ShadowFixView: React.FC<ShadowFixViewProps> = ({
  findings,
  onNavigate,
  onRunShadowFix,
  isActionRunning,
}) => {
  const activeFinding =
    findings.find(
      (f) =>
        f.status === 'verified' ||
        f.status === 'approved' ||
        f.status === 'sandbox_testing'
    ) || findings[0];

  const patch = activeFinding?.patch;
  const isVerified = activeFinding?.status === 'verified';

  const stages = [
    {
      name: 'Prepare isolated workspace',
      desc: 'Create ephemeral sandbox directory in /tmp/vulnseal-shadowfix-*',
      status: isVerified ? 'completed' : 'pending',
    },
    {
      name: 'Baseline validation',
      desc: 'Execute original deterministic test to confirm active vulnerability reproduction',
      status: isVerified ? 'completed' : 'pending',
    },
    {
      name: 'Apply approved patch',
      desc: `Inject approved patch into isolated workspace (SHA-256: ${patch?.sha256_hash.slice(0, 10) || '...'})`,
      status: isVerified ? 'completed' : 'pending',
    },
    {
      name: 'Build patched application',
      desc: 'Verify TypeScript compilation, syntax trees, and module import integrity',
      status: isVerified ? 'completed' : 'pending',
    },
    {
      name: 'Start patched application',
      desc: 'Boot digital twin service on isolated internal loopback port',
      status: isVerified ? 'completed' : 'pending',
    },
    {
      name: 'Replay original security check',
      desc: 'Execute identical security rule against patched endpoints to verify vulnerability closure',
      status: isVerified ? 'completed' : 'pending',
    },
    {
      name: 'Run regression test suite',
      desc: 'Execute 4/4 behavior assertions to guarantee existing session & auth flows did not break',
      status: isVerified ? 'completed' : 'pending',
    },
    {
      name: 'Independent verification',
      desc: 'IndependentVerifier validates all 4 gates and signs cryptographic Proof of Fix',
      status: isVerified ? 'completed' : 'pending',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-100 dark:border-slate-800">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
            Testing Fix in ShadowFix
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Your production application is not being modified. Testing occurs strictly within an ephemeral digital twin.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {patch && activeFinding.status === 'approved' && (
            <button
              onClick={() => onRunShadowFix(patch.id)}
              disabled={isActionRunning}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold shadow-xs transition-colors disabled:opacity-50"
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>{isActionRunning ? 'Executing Sandbox...' : 'Execute ShadowFix Verification'}</span>
            </button>
          )}

          {isVerified && (
            <button
              onClick={() => onNavigate('proofs')}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold shadow-xs"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>View Verified Proof →</span>
            </button>
          )}
        </div>
      </div>

      {/* Main Card */}
      <div className="rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-6 shadow-2xs">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">
              Digital Twin Execution Pipeline
            </h3>
            <p className="text-xs text-slate-400">
              Ephemeral process sandbox execution sequence
            </p>
          </div>
          <StatusBadge status={isVerified ? 'completed' : isActionRunning ? 'running' : 'waiting_approval'} />
        </div>

        {/* Steps List */}
        <div className="space-y-3">
          {stages.map((stage, idx) => {
            const isCompleted = isVerified || (isActionRunning && idx < 4);
            const isRunning = isActionRunning && idx === 4;

            return (
              <div
                key={idx}
                className="flex items-start gap-3.5 p-3 rounded-lg border border-slate-100 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-950/40"
              >
                <div className="mt-0.5 shrink-0">
                  {isCompleted ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                  ) : isRunning ? (
                    <Clock className="w-4 h-4 text-blue-600 dark:text-blue-400 animate-spin" />
                  ) : (
                    <div className="w-4 h-4 rounded-full border border-slate-300 dark:border-slate-700 flex items-center justify-center text-[10px] text-slate-500">
                      {idx + 1}
                    </div>
                  )}
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span
                      className={`text-xs font-semibold ${
                        isCompleted
                          ? 'text-slate-900 dark:text-white'
                          : 'text-slate-500 dark:text-slate-400'
                      }`}
                    >
                      {idx + 1}. {stage.name}
                    </span>
                    <span
                      className={`text-[10px] font-mono ${
                        isCompleted
                          ? 'text-emerald-600 dark:text-emerald-400 font-bold'
                          : isRunning
                          ? 'text-blue-600 dark:text-blue-400 font-bold'
                          : 'text-slate-400'
                      }`}
                    >
                      {isCompleted ? 'COMPLETED' : isRunning ? 'RUNNING...' : 'PENDING'}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed">
                    {stage.desc}
                  </p>
                </div>
              </div>
            );
          })}
        </div>

        {/* Invariants Footer */}
        <div className="p-4 rounded-lg border border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/60 text-xs space-y-2">
          <div className="font-semibold text-slate-800 dark:text-slate-200">
            IndependentVerifier Consensus Invariants:
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-slate-600 dark:text-slate-400 font-mono">
            <div className="flex items-center gap-1.5">
              <span className="text-emerald-600 font-bold">✓</span>
              <span>Security Replay == PASS</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-emerald-600 font-bold">✓</span>
              <span>Regression Test Suite == PASS</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-emerald-600 font-bold">✓</span>
              <span>Evidence Integrity == TRUE</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-emerald-600 font-bold">✓</span>
              <span>Patch Matches Approved SHA-256 == TRUE</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

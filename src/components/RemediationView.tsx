import React, { useState } from 'react';
import type { Finding, PatchCandidate, RootCause } from '../types/client';
import { DiffViewer } from './DiffViewer';
import { SeverityBadge } from './SeverityBadge';
import { StatusBadge } from './StatusBadge';
import {
  Wrench,
  CheckCircle2,
  XCircle,
  FileCode,
  ShieldCheck,
  Cpu,
  Info,
  ArrowRight,
  Shield,
  Layers,
} from 'lucide-react';
import { NavItem } from './Navigation';

interface RemediationViewProps {
  findings: Finding[];
  onApprovePatch: (patchId: string, patchHash: string, email: string) => Promise<void>;
  onRejectPatch: (patchId: string, reason: string, email: string) => Promise<void>;
  onRunShadowFix: (patchId: string) => Promise<void>;
  onNavigate: (tab: NavItem) => void;
  isActionRunning: boolean;
}

export const RemediationView: React.FC<RemediationViewProps> = ({
  findings,
  onApprovePatch,
  onRejectPatch,
  onRunShadowFix,
  onNavigate,
  isActionRunning,
}) => {
  const findingsWithRemediation = findings.filter(
    (f) =>
      Boolean(f.patch) ||
      f.status === 'remediation_ready' ||
      f.status === 'waiting_approval' ||
      f.status === 'approved' ||
      f.status === 'verified'
  );

  const [selectedFindingId, setSelectedFindingId] = useState<string>(
    findingsWithRemediation[0]?.id || findings[0]?.id || ''
  );

  const [approverEmail, setApproverEmail] = useState<string>('security-engineer@vulnseal.local');
  const [rejectReason, setRejectReason] = useState<string>('');
  const [showRejectModal, setShowRejectModal] = useState<boolean>(false);
  const [showApproveModal, setShowApproveModal] = useState<boolean>(false);

  const activeFinding = findings.find((f) => f.id === selectedFindingId);
  const patch = activeFinding?.patch;
  const rootCause = activeFinding?.rootCause || patch?.root_cause;
  const approval = activeFinding?.approval;

  const handleApprove = async () => {
    if (!patch) return;
    await onApprovePatch(patch.id, patch.sha256_hash, approverEmail);
    setShowApproveModal(false);
  };

  const handleReject = async () => {
    if (!patch) return;
    await onRejectPatch(patch.id, rejectReason, approverEmail);
    setShowRejectModal(false);
  };

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Page H1 Header and Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-100 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
            Fixes & Remediation
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Review and test minimal security code patches in an isolated digital twin.
          </p>
        </div>

        {findings.length > 0 && (
          <select
            value={selectedFindingId}
            onChange={(e) => setSelectedFindingId(e.target.value)}
            className="px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-white font-medium max-w-xs truncate"
          >
            {findings.map((f) => (
              <option key={f.id} value={f.id}>
                {f.title} ({f.rule_id})
              </option>
            ))}
          </select>
        )}
      </div>

      {!activeFinding || !patch ? (
        <div className="py-12 px-6 text-center rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-3 shadow-2xs max-w-xl mx-auto">
          <div className="w-10 h-10 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center mx-auto text-slate-400">
            <Wrench className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
              No fixes ready yet
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Select a confirmed finding and VulnSeal will trace its root cause and generate a minimal security patch.
            </p>
          </div>
          <button
            onClick={() => onNavigate('findings')}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs"
          >
            <span>View Findings</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Finding Context Header */}
          <div className="p-4 rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-2xs">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={activeFinding.severity} />
                <StatusBadge status={activeFinding.status} />
              </div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                {activeFinding.title}
              </h2>
              <div className="text-[11px] font-mono text-slate-500">
                Rule: {activeFinding.rule_id} · Target: {activeFinding.affected_url}
              </div>
            </div>

            <div className="shrink-0 flex items-center gap-2">
              {activeFinding.status === 'verified' && (
                <button
                  onClick={() => onNavigate('proofs')}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold shadow-xs"
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Inspect Proof of Fix</span>
                </button>
              )}

              {activeFinding.status === 'approved' && (
                <button
                  onClick={() => {
                    onRunShadowFix(patch.id);
                    onNavigate('shadowfix');
                  }}
                  disabled={isActionRunning}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold shadow-xs transition-colors disabled:opacity-50"
                >
                  <Cpu className="w-3.5 h-3.5" />
                  <span>Run ShadowFix Digital Twin →</span>
                </button>
              )}
            </div>
          </div>

          {/* Human-in-the-Loop Isolation Guarantee */}
          <div className="p-3.5 rounded-xl border border-blue-100 dark:border-blue-900/40 bg-blue-50/50 dark:bg-blue-950/20 flex items-start gap-2.5 text-xs text-blue-950 dark:text-blue-200">
            <Info className="w-4 h-4 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" />
            <div className="leading-relaxed">
              <strong>Human Isolation Guarantee:</strong> VulnSeal will apply and test this patch only inside an isolated ShadowFix digital twin sandbox. Your production application is not modified.
            </div>
          </div>

          {/* Two-Column Review Layout */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left 7 Cols: Source Code Diff & Test */}
            <div className="lg:col-span-7 space-y-4">
              <div className="p-5 rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-3 shadow-2xs">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-xs font-bold text-slate-900 dark:text-white">
                      Source Code Diff
                    </h3>
                    <span className="text-[11px] font-mono text-slate-400">
                      {patch.affected_file}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-400">
                    SHA-256: {patch.sha256_hash.slice(0, 12)}...
                  </span>
                </div>

                <DiffViewer diff={patch.diff} />
              </div>

              {/* Generated Regression Test */}
              <div className="p-5 rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-2 shadow-2xs">
                <span className="text-xs font-bold text-slate-900 dark:text-white block">
                  Generated Security Regression Test
                </span>
                <pre className="p-3 rounded-lg bg-slate-950 font-mono text-[11px] text-slate-200 overflow-x-auto">
                  {patch.generated_regression_test}
                </pre>
              </div>
            </div>

            {/* Right 5 Cols: Review & Approval Gate */}
            <div className="lg:col-span-5 space-y-4">
              <div className="p-5 rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-4 shadow-2xs">
                <h3 className="text-xs font-bold text-slate-900 dark:text-white pb-2 border-b border-slate-100 dark:border-slate-800">
                  Patch Review & Impact Assessment
                </h3>

                <div className="space-y-3 text-xs">
                  <div>
                    <span className="text-slate-400 block text-[11px]">Security Effect</span>
                    <p className="text-slate-700 dark:text-slate-300 font-medium mt-0.5">
                      {patch.security_effect}
                    </p>
                  </div>

                  <div>
                    <span className="text-slate-400 block text-[11px]">Implementation Risk</span>
                    <p className="text-slate-700 dark:text-slate-300 font-medium mt-0.5">
                      {patch.risk_assessment}
                    </p>
                  </div>

                  <div>
                    <span className="text-slate-400 block text-[11px]">Verification Strategy</span>
                    <p className="text-slate-700 dark:text-slate-300 font-medium mt-0.5">
                      {patch.verification_plan}
                    </p>
                  </div>
                </div>

                {/* Human Approval Action Gate */}
                <div className="pt-4 border-t border-slate-100 dark:border-slate-800">
                  {approval && approval.status === 'approved' ? (
                    <div className="space-y-3">
                      <div className="p-3 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-xs text-emerald-800 dark:text-emerald-300 flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                        <span>
                          Approved by <strong>{approval.approved_by_email}</strong>
                        </span>
                      </div>

                      {activeFinding.status !== 'verified' && (
                        <button
                          type="button"
                          onClick={() => {
                            onRunShadowFix(patch.id);
                            onNavigate('shadowfix');
                          }}
                          disabled={isActionRunning}
                          className="w-full py-2.5 px-4 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-xs transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
                        >
                          <Cpu className="w-4 h-4" />
                          <span>Run ShadowFix Verification →</span>
                        </button>
                      )}
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => setShowRejectModal(true)}
                          className="flex-1 py-2 px-3 rounded-lg border border-red-200 dark:border-red-900 bg-red-50/50 dark:bg-red-950/20 text-xs font-semibold text-red-700 dark:text-red-400 hover:bg-red-100 transition-colors"
                        >
                          Reject
                        </button>
                        <button
                          type="button"
                          onClick={() => setShowApproveModal(true)}
                          className="flex-1 py-2 px-3 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition-colors"
                        >
                          Approve & Test
                        </button>
                      </div>
                      <p className="text-[11px] text-slate-400 text-center">
                        Explicit human approval required before sandbox execution.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Approval Confirmation Modal */}
      {showApproveModal && patch && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">
              Approve Patch Candidate
            </h3>
            <p className="text-xs text-slate-500">
              You are approving this minimal code diff for execution in the isolated ShadowFix digital twin.
            </p>

            <div className="space-y-2 text-xs">
              <label className="font-semibold text-slate-700 dark:text-slate-300">
                Approver Email
              </label>
              <input
                type="email"
                value={approverEmail}
                onChange={(e) => setApproverEmail(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-900 dark:text-white font-mono text-xs"
              />
              <div className="text-[10px] font-mono text-slate-400">
                Cryptographic Patch Hash: {patch.sha256_hash.slice(0, 16)}...
              </div>
            </div>

            <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex justify-end gap-2">
              <button
                onClick={() => setShowApproveModal(false)}
                className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={handleApprove}
                className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-xs"
              >
                Sign & Approve
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Rejection Modal */}
      {showRejectModal && patch && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">
              Reject Patch Candidate
            </h3>
            <p className="text-xs text-slate-500">
              Discard this patch candidate and document operator feedback.
            </p>

            <div className="space-y-2 text-xs">
              <label className="font-semibold text-slate-700 dark:text-slate-300">
                Reason for Rejection
              </label>
              <textarea
                rows={3}
                value={rejectReason}
                onChange={(e) => setRejectReason(e.target.value)}
                placeholder="e.g. Scope of cookie change conflicts with internal SSO policy..."
                className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-900 dark:text-white text-xs"
              />
            </div>

            <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex justify-end gap-2">
              <button
                onClick={() => setShowRejectModal(false)}
                className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={handleReject}
                className="px-4 py-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white font-semibold text-xs shadow-xs"
              >
                Confirm Rejection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

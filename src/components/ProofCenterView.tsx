import React, { useState } from 'react';
import type { ProofOfFix } from '../types/client';
import { DiffViewer } from './DiffViewer';
import { VulnSealLogo } from './brand/VulnSealLogo';
import {
  ShieldCheck,
  CheckCircle2,
  Lock,
  Download,
  Copy,
  Check,
  Award,
  X,
  FileCode,
  ArrowRight,
  Shield,
  Layers,
} from 'lucide-react';

interface ProofCenterViewProps {
  proofs: ProofOfFix[];
}

export const ProofCenterView: React.FC<ProofCenterViewProps> = ({ proofs }) => {
  const [selectedProofId, setSelectedProofId] = useState<string>(
    proofs[0]?.id || ''
  );
  const [copied, setCopied] = useState<boolean>(false);
  const [showCertificate, setShowCertificate] = useState<boolean>(false);
  const [showPatchDiff, setShowPatchDiff] = useState<boolean>(false);

  const activeProof = proofs.find((p) => p.id === selectedProofId) || proofs[0];

  const handleCopyHash = () => {
    if (!activeProof) return;
    navigator.clipboard.writeText(activeProof.proof_hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportJSON = () => {
    if (!activeProof) return;
    const blob = new Blob([JSON.stringify(activeProof, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnseal-proof-${activeProof.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-100 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
            Proof Center
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-medium">
            Evidence-backed verification records. Don&apos;t just claim it was fixed &mdash; prove it.
          </p>
        </div>

        {proofs.length > 0 && (
          <div className="flex items-center gap-2">
            <select
              value={selectedProofId}
              onChange={(e) => setSelectedProofId(e.target.value)}
              className="px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-white font-mono"
            >
              {proofs.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.rule_id} · {p.proof_hash.slice(0, 10)}...
                </option>
              ))}
            </select>

            <button
              onClick={() => setShowCertificate(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-300 text-xs font-semibold hover:bg-emerald-100 transition-colors shadow-2xs"
            >
              <Award className="w-3.5 h-3.5" />
              <span>Audit Certificate</span>
            </button>

            <button
              onClick={handleExportJSON}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors shadow-2xs"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Record</span>
            </button>
          </div>
        )}
      </div>

      {!activeProof ? (
        <div className="py-12 px-6 text-center rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-3 shadow-2xs max-w-xl mx-auto">
          <div className="w-10 h-10 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center mx-auto text-slate-400">
            <ShieldCheck className="w-5 h-5 text-emerald-500" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
              No verified fixes yet
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Proof records appear after an approved patch passes security replay, regression testing, and independent verification.
            </p>
          </div>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Flagship Verified Header Banner */}
          <div className="p-6 rounded-xl border border-emerald-500/50 bg-emerald-50/40 dark:bg-emerald-950/20 space-y-4 shadow-2xs">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-md bg-emerald-100 dark:bg-emerald-900/80 text-emerald-800 dark:text-emerald-200 text-xs font-bold tracking-wide">
                  <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                  <span>VERIFIED SECURITY REPAIR ✓</span>
                </div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white pt-1">
                  {activeProof.rule_title}
                </h2>
                <div className="text-xs text-slate-600 dark:text-slate-400 font-mono">
                  Target: {activeProof.target_url} · Rule ID: {activeProof.rule_id}
                </div>
              </div>

              {/* Cryptographic Proof Hash */}
              <div className="p-3 rounded-lg border border-emerald-200 dark:border-emerald-800 bg-white dark:bg-slate-900 space-y-1 text-right shrink-0">
                <span className="text-[10px] text-slate-400 block font-mono">
                  CRYPTOGRAPHIC PROOF HASH (SHA-256)
                </span>
                <div className="flex items-center justify-end gap-2">
                  <span className="font-mono text-xs font-bold text-emerald-600 dark:text-emerald-400">
                    {activeProof.proof_hash.slice(0, 18)}...
                  </span>
                  <button
                    onClick={handleCopyHash}
                    className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500 hover:text-slate-800"
                    title="Copy full cryptographic SHA-256 hash"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>

            {/* Audit Metadata Line */}
            <div className="pt-3 border-t border-emerald-200/60 dark:border-emerald-900/60 flex flex-wrap items-center gap-y-2 gap-x-6 text-[11px] font-mono text-slate-600 dark:text-slate-400">
              <div>
                <span>Approved By: </span>
                <strong className="text-slate-900 dark:text-white">{activeProof.approved_by}</strong>
              </div>
              <div>
                <span>Verified At: </span>
                <strong className="text-slate-900 dark:text-white">
                  {new Date(activeProof.verified_at).toLocaleString()}
                </strong>
              </div>
              <div>
                <span>Verifier: </span>
                <strong className="text-emerald-600 dark:text-emerald-400">IndependentVerifier</strong>
              </div>
              <div>
                <span>Remediation Twin: </span>
                <strong className="text-slate-900 dark:text-white">ShadowFix Digital Twin</strong>
              </div>
            </div>
          </div>

          {/* Core Side-by-Side Comparison: BEFORE vs AFTER */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* BEFORE Card */}
            <div className="rounded-xl border border-red-200 dark:border-red-900/60 bg-red-50/20 dark:bg-red-950/10 p-5 space-y-4 shadow-2xs">
              <div className="flex items-center justify-between pb-2 border-b border-red-200/60 dark:border-red-900/40">
                <span className="text-xs font-bold tracking-wide text-red-700 dark:text-red-400">
                  ORIGINAL OBSERVATION (BEFORE)
                </span>
                <span className="text-[11px] font-mono font-semibold text-red-600 dark:text-red-400">
                  REPRODUCED
                </span>
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex items-center justify-between py-1 border-b border-red-100 dark:border-red-900/20">
                  <span className="text-slate-500">Security Attribute</span>
                  <span className="font-mono font-bold text-red-600 dark:text-red-400">
                    {activeProof.before_evidence.attribute_status}
                  </span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-red-100 dark:border-red-900/20">
                  <span className="text-slate-500">Condition Reproduction</span>
                  <span className="font-mono font-bold text-red-700 dark:text-red-300">REPRODUCED</span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-red-100 dark:border-red-900/20">
                  <span className="text-slate-500">Original Security Check</span>
                  <span className="font-mono font-bold text-red-600 dark:text-red-400">
                    FAIL (Vulnerable)
                  </span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-red-200 dark:border-red-900/60 font-mono text-xs space-y-1">
                <span className="text-[10px] text-slate-400 block">OBSERVED RAW EXCERPT</span>
                <div className="text-slate-800 dark:text-slate-200 break-all text-[11px]">
                  {activeProof.before_evidence.raw_header}
                </div>
              </div>
            </div>

            {/* AFTER Card */}
            <div className="rounded-xl border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/20 dark:bg-emerald-950/10 p-5 space-y-4 shadow-2xs">
              <div className="flex items-center justify-between pb-2 border-b border-emerald-200/60 dark:border-emerald-900/40">
                <span className="text-xs font-bold tracking-wide text-emerald-700 dark:text-emerald-400">
                  INDEPENDENT REPLAY (AFTER PATCH)
                </span>
                <span className="text-[11px] font-mono font-semibold text-emerald-600 dark:text-emerald-400">
                  RESOLVED &amp; CLOSED
                </span>
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex items-center justify-between py-1 border-b border-emerald-100 dark:border-emerald-900/20">
                  <span className="text-slate-500">Security Attribute</span>
                  <span className="font-mono font-bold text-emerald-600 dark:text-emerald-400">
                    {activeProof.after_evidence.attribute_status}
                  </span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-emerald-100 dark:border-emerald-900/20">
                  <span className="text-slate-500">Condition Reproduction</span>
                  <span className="font-mono font-bold text-emerald-700 dark:text-emerald-300">RESOLVED</span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-emerald-100 dark:border-emerald-900/20">
                  <span className="text-slate-500">Original Security Check</span>
                  <span className="font-mono font-bold text-emerald-600 dark:text-emerald-400">
                    PASS (Verified)
                  </span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-emerald-200 dark:border-emerald-900/60 font-mono text-xs space-y-1">
                <span className="text-[10px] text-slate-400 block">REPLAYED RAW EXCERPT</span>
                <div className="text-slate-800 dark:text-slate-200 break-all text-[11px]">
                  {activeProof.after_evidence.raw_header}
                </div>
              </div>
            </div>
          </div>

          {/* Applied Patch Diff and Root Cause File */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-3 shadow-2xs">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-xs font-bold text-slate-900 dark:text-white">
                  Applied Source Patch &amp; Cryptographic Hash
                </h3>
                <div className="text-[11px] font-mono text-slate-500">
                  Target File: {activeProof.root_cause_file}:{activeProof.root_cause_line}
                </div>
              </div>
              <button
                onClick={() => setShowPatchDiff(!showPatchDiff)}
                className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline"
              >
                {showPatchDiff ? 'Hide Diff' : 'View Code Diff'}
              </button>
            </div>

            {showPatchDiff && (
              <div className="pt-2">
                <DiffViewer diff={activeProof.patch_diff} />
              </div>
            )}
          </div>
        </div>
      )}

      {/* Certificate Modal */}
      {showCertificate && activeProof && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-xs">
          <div className="w-full max-w-xl rounded-xl border-2 border-emerald-500 bg-white dark:bg-slate-900 p-6 shadow-2xl space-y-5 animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between pb-3 border-b border-emerald-200 dark:border-emerald-800">
              <div className="flex items-center gap-2.5">
                <VulnSealLogo size="xs" />
                <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider font-mono">
                  VulnSeal Proof of Fix Certificate
                </h3>
              </div>
              <button
                onClick={() => setShowCertificate(false)}
                className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1.5">
                <div>RECORD ID: {activeProof.id}</div>
                <div>RULE: {activeProof.rule_title} ({activeProof.rule_id})</div>
                <div>TARGET: {activeProof.target_url}</div>
                <div>ROOT CAUSE: {activeProof.root_cause_file}:{activeProof.root_cause_line}</div>
                <div>APPROVED BY: {activeProof.approved_by}</div>
                <div>VERIFIED AT: {activeProof.verified_at}</div>
                <div className="pt-1.5 border-t border-slate-200 dark:border-slate-800 text-emerald-600 dark:text-emerald-400 break-all font-bold">
                  SHA-256 PROOF HASH: {activeProof.proof_hash}
                </div>
              </div>
            </div>

            <div className="pt-2 flex justify-end gap-2">
              <button
                onClick={handleExportJSON}
                className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-xs shadow-xs"
              >
                Download Certificate JSON
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

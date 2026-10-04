import React, { useState } from 'react';
import type { Target } from '../types/client';
import { StatusBadge } from './StatusBadge';
import {
  Plus,
  ShieldCheck,
  Globe,
  Play,
  X,
  Copy,
  Check,
  RefreshCw,
  Trash2,
  ExternalLink,
  Shield,
  Layers,
  ArrowRight,
} from 'lucide-react';
import { verifyTarget, createTarget, fetchTargetChallenge, deleteTarget } from '../lib/api';

interface TargetsViewProps {
  targets: Target[];
  onRefresh: () => Promise<void>;
  onStartScan: (targetId: string) => Promise<void>;
  isScanning: boolean;
}

export const TargetsView: React.FC<TargetsViewProps> = ({
  targets,
  onRefresh,
  onStartScan,
  isScanning,
}) => {
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedTarget, setSelectedTarget] = useState<Target | null>(null);
  const [verifyingTarget, setVerifyingTarget] = useState<Target | null>(null);
  const [newUrl, setNewUrl] = useState('');
  const [newName, setNewName] = useState('');
  const [pendingChallenge, setPendingChallenge] = useState<any>(null);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [copied, setCopied] = useState(false);
  const [developerConfirmed, setDeveloperConfirmed] = useState(false);
  const [activeDrawerTab, setActiveDrawerTab] = useState<'overview' | 'scope' | 'authorization'>('overview');

  const handleCreateTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUrl || !newName) return;
    setSubmitting(true);
    setErrorMsg(null);

    try {
      const isDemo = newUrl.includes('demo-target');
      const result = await createTarget({
        url: newUrl,
        name: newName,
        is_demo: isDemo,
      });

      await onRefresh();
      setShowAddModal(false);
      setNewUrl('');
      setNewName('');

      if (!isDemo) {
        setPendingChallenge(result.challenge);
        setVerifyingTarget(result.target);
      }
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const openVerifyDialog = async (target: Target) => {
    setVerifyingTarget(target);
    setErrorMsg(null);
    setDeveloperConfirmed(false);
    try {
      const challenge = await fetchTargetChallenge(target.id);
      setPendingChallenge(challenge);
    } catch (err: any) {
      setErrorMsg(err.message);
    }
  };

  const handleCheckMetaTag = async (targetId: string) => {
    setVerifyingId(targetId);
    setErrorMsg(null);
    try {
      await verifyTarget(targetId);
      await onRefresh();
      setVerifyingTarget(null);
      setPendingChallenge(null);
      if (selectedTarget?.id === targetId) {
        setSelectedTarget((prev) => (prev ? { ...prev, status: 'authorized' } : null));
      }
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setVerifyingId(null);
    }
  };

  const handleDeveloperConfirm = async (targetId: string) => {
    setVerifyingId(targetId);
    setErrorMsg(null);
    try {
      await verifyTarget(targetId, {
        developer_confirm: true,
        owner_email: 'security-engineer@vulnseal.local',
      });
      await onRefresh();
      setVerifyingTarget(null);
      setPendingChallenge(null);
      if (selectedTarget?.id === targetId) {
        setSelectedTarget((prev) => (prev ? { ...prev, status: 'authorized' } : null));
      }
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setVerifyingId(null);
    }
  };

  const handleDeleteTarget = async (target: Target) => {
    if (window.confirm(`Are you sure you want to delete target "${target.name}"?`)) {
      try {
        await deleteTarget(target.id);
        if (selectedTarget?.id === target.id) setSelectedTarget(null);
        await onRefresh();
      } catch (err: any) {
        alert(err.message);
      }
    }
  };

  const handleCopyTag = (token: string) => {
    const tag = `<meta name="vulnseal-verification" content="${token}" />`;
    navigator.clipboard.writeText(tag);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Page H1 Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-100 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
            Targets
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Manage authorized application domains and ownership verification challenges.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onRefresh}
            className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors shadow-2xs"
            title="Refresh targets"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Target</span>
          </button>
        </div>
      </div>

      {/* Targets Table */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-2xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50/80 dark:bg-slate-950/60 text-slate-500 dark:text-slate-400 font-mono text-[11px] border-b border-slate-200 dark:border-slate-800 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Target Application</th>
                <th className="py-3 px-4">Authorization</th>
                <th className="py-3 px-4">Security Score</th>
                <th className="py-3 px-4">Open Findings</th>
                <th className="py-3 px-4">Last Scanned</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
              {targets.map((target) => (
                <tr
                  key={target.id}
                  onClick={() => setSelectedTarget(target)}
                  className="hover:bg-slate-50/60 dark:hover:bg-slate-800/40 cursor-pointer transition-colors"
                >
                  <td className="py-3.5 px-4">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-lg bg-slate-100 dark:bg-slate-800 flex items-center justify-center text-slate-600 dark:text-slate-300 shrink-0 border border-slate-200 dark:border-slate-700">
                        <Globe className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                      </div>
                      <div className="min-w-0">
                        <div className="font-semibold text-slate-900 dark:text-white truncate flex items-center gap-1.5">
                          <span>{target.name}</span>
                          {target.is_demo && (
                            <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-900">
                              DEMO SANDBOX
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 truncate mt-0.5">
                          {target.url}
                        </div>
                      </div>
                    </div>
                  </td>

                  <td className="py-3.5 px-4">
                    <StatusBadge status={target.status} />
                  </td>

                  <td className="py-3.5 px-4">
                    {target.security_score !== null && target.security_score !== undefined ? (
                      <div className="flex items-baseline gap-1">
                        <span className="font-mono font-bold text-slate-900 dark:text-white">
                          {target.security_score}
                        </span>
                        <span className="text-[10px] text-slate-400">/ 100</span>
                      </div>
                    ) : (
                      <span className="text-slate-400 dark:text-slate-500 font-mono font-semibold" title="Not assessed yet">
                        —
                      </span>
                    )}
                  </td>

                  <td className="py-3.5 px-4 font-mono tabular-nums">
                    {target.last_scan_at ? (
                      <span
                        className={
                          target.open_findings_count > 0
                            ? 'font-bold text-amber-600 dark:text-amber-400'
                            : 'text-slate-600 dark:text-slate-400 font-semibold'
                        }
                      >
                        {target.open_findings_count}
                      </span>
                    ) : (
                      <span className="text-slate-400 dark:text-slate-500 font-mono">—</span>
                    )}
                  </td>

                  <td className="py-3.5 px-4 text-slate-500 dark:text-slate-400 text-[11px] font-mono">
                    {target.last_scan_at
                      ? new Date(target.last_scan_at).toLocaleTimeString()
                      : 'Never'}
                  </td>

                  <td className="py-3.5 px-4 text-right">
                    <div
                      className="inline-flex items-center gap-1.5"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {target.status === 'authorized' ? (
                        <button
                          onClick={() => onStartScan(target.id)}
                          disabled={isScanning}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 hover:bg-blue-100 font-semibold text-xs transition-colors shadow-2xs disabled:opacity-50"
                        >
                          <Play className="w-3 h-3 fill-current" />
                          <span>Scan</span>
                        </button>
                      ) : (
                        <button
                          onClick={() => openVerifyDialog(target)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 hover:bg-amber-100 font-semibold text-xs transition-colors shadow-2xs"
                        >
                          <RefreshCw className="w-3 h-3" />
                          <span>Verify</span>
                        </button>
                      )}

                      {!target.is_demo && (
                        <button
                          onClick={() => handleDeleteTarget(target)}
                          title="Delete target"
                          className="p-1.5 rounded text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-950/40 transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}

              {targets.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-xs text-slate-500">
                    No target applications configured. Click &quot;Add Target&quot; to register an authorized domain.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Target Detail Drawer */}
      {selectedTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-end bg-slate-950/40 backdrop-blur-xs">
          <div className="w-full max-w-lg h-full bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 p-6 shadow-2xl flex flex-col justify-between overflow-y-auto animate-in slide-in-from-right duration-200">
            <div className="space-y-5">
              {/* Drawer Header */}
              <div className="flex items-start justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
                <div className="min-w-0 pr-4">
                  <div className="flex items-center gap-2 mb-1.5">
                    <StatusBadge status={selectedTarget.status} />
                    {selectedTarget.is_demo && (
                      <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-900">
                        DEMO SANDBOX
                      </span>
                    )}
                  </div>
                  <h2 className="text-base font-bold text-slate-900 dark:text-white truncate">
                    {selectedTarget.name}
                  </h2>
                  <div className="text-xs font-mono text-slate-500 mt-0.5 break-all">
                    {selectedTarget.url}
                  </div>
                </div>
                <button
                  onClick={() => setSelectedTarget(null)}
                  className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Drawer Tabs */}
              <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 text-xs">
                <button
                  type="button"
                  onClick={() => setActiveDrawerTab('overview')}
                  className={`pb-2 px-1 font-medium border-b-2 transition-colors ${
                    activeDrawerTab === 'overview'
                      ? 'border-blue-600 text-blue-600 dark:text-blue-400 font-semibold'
                      : 'border-transparent text-slate-500 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Overview
                </button>
                <button
                  type="button"
                  onClick={() => setActiveDrawerTab('scope')}
                  className={`pb-2 px-1 font-medium border-b-2 transition-colors ${
                    activeDrawerTab === 'scope'
                      ? 'border-blue-600 text-blue-600 dark:text-blue-400 font-semibold'
                      : 'border-transparent text-slate-500 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Scope & Policy
                </button>
                <button
                  type="button"
                  onClick={() => setActiveDrawerTab('authorization')}
                  className={`pb-2 px-1 font-medium border-b-2 transition-colors ${
                    activeDrawerTab === 'authorization'
                      ? 'border-blue-600 text-blue-600 dark:text-blue-400 font-semibold'
                      : 'border-transparent text-slate-500 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  Authorization
                </button>
              </div>

              {/* Tab Content */}
              {activeDrawerTab === 'overview' && (
                <div className="space-y-4 text-xs">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800 space-y-1">
                      <span className="text-slate-400 text-[11px]">Security Score</span>
                      <div className="text-lg font-bold font-mono text-slate-900 dark:text-white">
                        {selectedTarget.security_score !== null ? `${selectedTarget.security_score}/100` : '—'}
                      </div>
                    </div>
                    <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800 space-y-1">
                      <span className="text-slate-400 text-[11px]">Last Scan</span>
                      <div className="text-xs font-mono font-medium text-slate-700 dark:text-slate-300">
                        {selectedTarget.last_scan_at ? new Date(selectedTarget.last_scan_at).toLocaleString() : 'Never scanned'}
                      </div>
                    </div>
                  </div>

                  <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800 space-y-2">
                    <span className="font-semibold text-slate-900 dark:text-white block">
                      Target State Summary
                    </span>
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div>
                        <span className="text-slate-400">Open Findings:</span>
                        <div className="font-bold font-mono text-slate-800 dark:text-slate-200">
                          {selectedTarget.open_findings_count}
                        </div>
                      </div>
                      <div>
                        <span className="text-slate-400">Verified Fixes:</span>
                        <div className="font-bold font-mono text-emerald-600 dark:text-emerald-400">
                          {selectedTarget.verified_fixes_count}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {activeDrawerTab === 'scope' && (
                <div className="space-y-3 text-xs">
                  <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800 space-y-2">
                    <span className="font-semibold text-slate-900 dark:text-white block">
                      ScopeGuard Policy Boundaries
                    </span>
                    <div className="space-y-1 text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                      <div>Allowed Origin: {selectedTarget.url}</div>
                      <div>Max Crawl Depth: 3 levels</div>
                      <div>Rate Limit: 5 requests / sec</div>
                      <div>Request Budget: 30 requests / scan</div>
                      <div>SSRF Protection: Enforced (RFC 1918 + Cloud Metadata blocked)</div>
                    </div>
                  </div>
                </div>
              )}

              {activeDrawerTab === 'authorization' && (
                <div className="space-y-3 text-xs">
                  <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800 space-y-2">
                    <span className="font-semibold text-slate-900 dark:text-white block">
                      Ownership Verification Status
                    </span>
                    <div className="text-[11px] text-slate-600 dark:text-slate-400 space-y-1">
                      <div>Status: <strong>{selectedTarget.status.toUpperCase()}</strong></div>
                      {selectedTarget.authorized_at && (
                        <div>Authorized at: {new Date(selectedTarget.authorized_at).toLocaleString()}</div>
                      )}
                    </div>
                  </div>

                  {selectedTarget.status !== 'authorized' && (
                    <button
                      onClick={() => {
                        const target = selectedTarget;
                        setSelectedTarget(null);
                        openVerifyDialog(target);
                      }}
                      className="w-full py-2 px-3 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-medium text-xs shadow-xs"
                    >
                      Verify Ownership Now
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* Drawer Footer Actions */}
            <div className="pt-4 border-t border-slate-100 dark:border-slate-800 flex items-center gap-2">
              <button
                onClick={() => setSelectedTarget(null)}
                className="py-2 px-3 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
              >
                Close
              </button>
              {!selectedTarget.is_demo && (
                <button
                  onClick={() => handleDeleteTarget(selectedTarget)}
                  className="py-2 px-3 rounded-lg border border-red-200 dark:border-red-900 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40 text-xs font-medium flex items-center gap-1 transition-colors"
                  title="Delete this target"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Delete</span>
                </button>
              )}
              {selectedTarget.status === 'authorized' && (
                <button
                  onClick={() => {
                    const id = selectedTarget.id;
                    setSelectedTarget(null);
                    onStartScan(id);
                  }}
                  disabled={isScanning}
                  className="flex-1 py-2 px-3 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs disabled:opacity-50 flex items-center justify-center gap-1.5"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>{isScanning ? 'Scan Running...' : 'Launch Scan'}</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Target Ownership Verification Modal */}
      {verifyingTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-xs">
          <div className="w-full max-w-lg rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-2xl space-y-5 animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-blue-600" />
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                    Authorize Target Ownership
                  </h3>
                </div>
                <p className="text-[11px] font-mono text-slate-500 truncate max-w-md">
                  {verifyingTarget.name} · {verifyingTarget.url}
                </p>
              </div>
              <button
                onClick={() => {
                  setVerifyingTarget(null);
                  setErrorMsg(null);
                }}
                className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {errorMsg && (
              <div className="p-3.5 rounded-lg bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 text-xs text-red-700 dark:text-red-300 leading-relaxed">
                <strong>Verification Note:</strong> {errorMsg}
              </div>
            )}

            <div className="space-y-4 text-xs">
              {/* Method 1: HTML Meta Tag */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-900 dark:text-white">
                    Method 1: HTML Meta Tag Verification
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopyTag(pendingChallenge?.token || 'vs_token_challenge')}
                    className="inline-flex items-center gap-1 text-[11px] text-blue-600 dark:text-blue-400 hover:underline"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied Tag' : 'Copy HTML Tag'}</span>
                  </button>
                </div>

                <p className="text-[11px] text-slate-500 leading-relaxed">
                  Place this verification tag in the <code className="font-mono">&lt;head&gt;</code> of your website homepage:
                </p>

                <div className="p-2.5 rounded bg-slate-950 font-mono text-[11px] text-emerald-400 select-all break-all border border-slate-800">
                  {`<meta name="vulnseal-verification" content="${pendingChallenge?.token || 'vs_token_...'}" />`}
                </div>

                <button
                  type="button"
                  onClick={() => handleCheckMetaTag(verifyingTarget.id)}
                  disabled={verifyingId !== null}
                  className="w-full py-2 px-3 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${verifyingId !== null ? 'animate-spin' : ''}`} />
                  <span>{verifyingId !== null ? 'Checking Homepage...' : 'Verify Meta Tag on Target'}</span>
                </button>
              </div>

              {/* Method 2: Developer / Owner Instant Sign-Off */}
              <div className="p-4 rounded-xl bg-blue-50/40 dark:bg-blue-950/20 border border-blue-200/80 dark:border-blue-900/50 space-y-3">
                <span className="font-semibold text-slate-900 dark:text-white block">
                  Method 2: Developer Owner Direct Declaration
                </span>
                <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                  For staging, preview, or internal development environments, you can sign an authorized owner declaration to immediately activate defensive scanning.
                </p>

                <label className="flex items-start gap-2.5 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={developerConfirmed}
                    onChange={(e) => setDeveloperConfirmed(e.target.checked)}
                    className="mt-0.5 rounded text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-[11px] text-slate-700 dark:text-slate-300 leading-snug">
                    I confirm that I own or hold written authorization to scan <strong>{verifyingTarget.url}</strong> under ScopeGuard boundaries.
                  </span>
                </label>

                <button
                  type="button"
                  onClick={() => handleDeveloperConfirm(verifyingTarget.id)}
                  disabled={!developerConfirmed || verifyingId !== null}
                  className="w-full py-2 px-3 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-xs transition-colors disabled:opacity-50"
                >
                  {verifyingId !== null ? 'Authorizing Target...' : 'Sign Declaration & Authorize'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add Target Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                Add Authorized Target
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {errorMsg && (
              <div className="p-3 rounded-lg bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900 text-xs text-red-700 dark:text-red-300">
                {errorMsg}
              </div>
            )}

            <form onSubmit={handleCreateTarget} className="space-y-4 text-xs">
              <div className="space-y-1.5">
                <label className="font-semibold text-slate-800 dark:text-slate-200">
                  Target Name
                </label>
                <input
                  type="text"
                  placeholder="e.g. Production API, Staging Web Portal"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  required
                  className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-900 dark:text-white focus:outline-hidden focus:border-blue-500"
                />
              </div>

              <div className="space-y-1.5">
                <label className="font-semibold text-slate-800 dark:text-slate-200">
                  Target URL
                </label>
                <input
                  type="url"
                  placeholder="https://example.com"
                  value={newUrl}
                  onChange={(e) => setNewUrl(e.target.value)}
                  required
                  className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-900 dark:text-white focus:outline-hidden focus:border-blue-500 font-mono text-[11px]"
                />
                <p className="text-[10px] text-slate-400">
                  Must be an accessible HTTP/HTTPS URL that you own or have permission to inspect.
                </p>
              </div>

              <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-xs disabled:opacity-50"
                >
                  {submitting ? 'Registering...' : 'Register Target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

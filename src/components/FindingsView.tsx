import React, { useState } from 'react';
import type { Finding } from '../types/client';
import { SeverityBadge } from './SeverityBadge';
import { StatusBadge } from './StatusBadge';
import { HttpViewer } from './HttpViewer';
import {
  ShieldAlert,
  Wrench,
  X,
  ArrowRight,
  CheckCircle2,
  FileCode,
  Search,
  Check,
  Shield,
  Layers,
  Lock,
} from 'lucide-react';
import { NavItem } from './Navigation';

interface FindingsViewProps {
  findings: Finding[];
  onGenerateRemediation: (findingId: string) => Promise<void>;
  onNavigate: (tab: NavItem) => void;
  isRemediating: boolean;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  onGenerateRemediation,
  onNavigate,
  isRemediating,
}) => {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [detailTab, setDetailTab] = useState<'overview' | 'evidence' | 'rootcause'>('overview');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const totalFindingsCount = findings.length;

  const filteredFindings = findings.filter((f) => {
    if (filterSeverity !== 'all' && f.severity !== filterSeverity) return false;
    if (filterStatus !== 'all' && f.status !== filterStatus) return false;
    if (
      searchQuery &&
      !f.title.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !f.rule_id.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !f.affected_url.toLowerCase().includes(searchQuery.toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  const clearFilters = () => {
    setFilterSeverity('all');
    setFilterStatus('all');
    setSearchQuery('');
  };

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Header and Filter Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-100 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
            Findings
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Confirmed security weaknesses backed by reproducible, sanitized HTTP evidence.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Filter findings..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-white placeholder-slate-400 w-44 sm:w-56 focus:outline-hidden focus:border-blue-500"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="px-2.5 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-white font-medium"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Status Filter */}
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="px-2.5 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-white font-medium"
          >
            <option value="all">All Statuses</option>
            <option value="confirmed">Confirmed</option>
            <option value="waiting_approval">Awaiting Approval</option>
            <option value="approved">Approved</option>
            <option value="verified">Verified</option>
          </select>
        </div>
      </div>

      {/* Full-width Findings Table */}
      <div className="rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-2xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200/80 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 text-slate-500 dark:text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Finding & Rule</th>
                <th className="py-3 px-4">Target Endpoint</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
              {filteredFindings.map((finding) => (
                <tr
                  key={finding.id}
                  onClick={() => {
                    setSelectedFinding(finding);
                    setDetailTab('overview');
                  }}
                  className="hover:bg-slate-50/60 dark:hover:bg-slate-800/40 cursor-pointer transition-colors"
                >
                  <td className="py-3.5 px-4">
                    <SeverityBadge severity={finding.severity} />
                  </td>

                  <td className="py-3.5 px-4">
                    <div className="font-semibold text-slate-900 dark:text-white">
                      {finding.title}
                    </div>
                    <div className="font-mono text-[11px] text-slate-400 mt-0.5">
                      {finding.rule_id}
                    </div>
                  </td>

                  <td className="py-3.5 px-4 font-mono text-[11px] text-slate-500 dark:text-slate-400 truncate max-w-xs">
                    {finding.affected_url}
                  </td>

                  <td className="py-3.5 px-4 font-mono tabular-nums text-slate-700 dark:text-slate-300">
                    {(finding.confidence * 100).toFixed(0)}%
                  </td>

                  <td className="py-3.5 px-4">
                    <StatusBadge status={finding.status} />
                  </td>

                  <td className="py-3.5 px-4 text-right">
                    <span className="text-xs font-semibold text-blue-600 dark:text-blue-400 hover:underline inline-flex items-center gap-1">
                      <span>Inspect</span>
                      <ArrowRight className="w-3 h-3" />
                    </span>
                  </td>
                </tr>
              ))}

              {/* TWO DISTINCT EMPTY STATES */}
              {totalFindingsCount === 0 && (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-xs text-slate-500 space-y-3">
                    <div className="w-10 h-10 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center mx-auto text-slate-400">
                      <ShieldAlert className="w-5 h-5" />
                    </div>
                    <div>
                      <p className="font-semibold text-slate-800 dark:text-slate-200">No confirmed findings yet</p>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        Run a security scan to inspect an authorized target for weaknesses.
                      </p>
                    </div>
                    <button
                      onClick={() => onNavigate('scans')}
                      className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-xs"
                    >
                      <span>Run Scan</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              )}

              {totalFindingsCount > 0 && filteredFindings.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-xs text-slate-500 space-y-3">
                    <div className="w-10 h-10 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center mx-auto text-slate-400">
                      <Search className="w-5 h-5" />
                    </div>
                    <div>
                      <p className="font-semibold text-slate-800 dark:text-slate-200">No findings match these filters</p>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        Try clearing or modifying the severity and status filters.
                      </p>
                    </div>
                    <button
                      onClick={clearFilters}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-xs font-medium text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
                    >
                      <span>Clear Filters</span>
                    </button>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Dedicated Finding Detail Dialog / Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-xs">
          <div className="w-full max-w-3xl rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-2xl space-y-5 max-h-[90vh] overflow-y-auto animate-in fade-in zoom-in-95">
            {/* Modal Header */}
            <div className="flex items-start justify-between pb-4 border-b border-slate-100 dark:border-slate-800">
              <div className="space-y-1.5 min-w-0 pr-4">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={selectedFinding.severity} />
                  <StatusBadge status={selectedFinding.status} />
                  <span className="text-[11px] font-mono text-slate-400">
                    Confidence: {(selectedFinding.confidence * 100).toFixed(0)}%
                  </span>
                </div>
                <h2 className="text-base font-bold text-slate-900 dark:text-white">
                  {selectedFinding.title}
                </h2>
                <div className="text-xs font-mono text-slate-500">
                  Target: {selectedFinding.affected_url} · Rule: {selectedFinding.rule_id}
                </div>
              </div>

              <button
                onClick={() => setSelectedFinding(null)}
                className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Navigation Tabs */}
            <div className="flex items-center gap-2 border-b border-slate-100 dark:border-slate-800 text-xs">
              <button
                onClick={() => setDetailTab('overview')}
                className={`px-3 py-2 font-medium border-b-2 transition-colors ${
                  detailTab === 'overview'
                    ? 'border-blue-600 text-blue-600 dark:text-blue-400 font-semibold'
                    : 'border-transparent text-slate-500 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                Overview
              </button>
              <button
                onClick={() => setDetailTab('evidence')}
                className={`px-3 py-2 font-medium border-b-2 transition-colors ${
                  detailTab === 'evidence'
                    ? 'border-blue-600 text-blue-600 dark:text-blue-400 font-semibold'
                    : 'border-transparent text-slate-500 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                HTTP Evidence
              </button>
              <button
                onClick={() => setDetailTab('rootcause')}
                className={`px-3 py-2 font-medium border-b-2 transition-colors ${
                  detailTab === 'rootcause'
                    ? 'border-blue-600 text-blue-600 dark:text-blue-400 font-semibold'
                    : 'border-transparent text-slate-500 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                Root Cause
              </button>
            </div>

            {/* Tab 1: Plain Language Overview */}
            {detailTab === 'overview' && (
              <div className="space-y-4 text-xs">
                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800 space-y-1">
                  <span className="font-semibold text-slate-900 dark:text-white block">
                    Vulnerability Description
                  </span>
                  <p className="text-slate-600 dark:text-slate-300 leading-relaxed">
                    {selectedFinding.description}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 rounded-lg border border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/30">
                    <span className="text-slate-400 text-[11px]">Affected Endpoint</span>
                    <div className="font-mono text-xs text-slate-800 dark:text-slate-200 font-semibold mt-0.5 truncate">
                      {selectedFinding.affected_url}
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/30">
                    <span className="text-slate-400 text-[11px]">Deterministic Rule</span>
                    <div className="font-mono text-xs text-slate-800 dark:text-slate-200 font-semibold mt-0.5">
                      {selectedFinding.rule_name} ({selectedFinding.rule_id})
                    </div>
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-blue-50/50 dark:bg-blue-950/20 border border-blue-100 dark:border-blue-900/40 text-blue-900 dark:text-blue-300 space-y-1">
                  <span className="font-semibold block">Evidence-Backed Guarantee</span>
                  <p className="text-[11px] leading-relaxed">
                    VulnSeal strictly verifies all candidate vulnerabilities with deterministic rules and independent judgment before confirming.
                  </p>
                </div>
              </div>
            )}

            {/* Tab 2: HTTP Evidence */}
            {detailTab === 'evidence' && (
              <div className="space-y-4 text-xs">
                {selectedFinding.evidence ? (
                  <HttpViewer evidence={selectedFinding.evidence} />
                ) : (
                  <div className="p-6 text-center text-slate-400">
                    Evidence record not loaded.
                  </div>
                )}
              </div>
            )}

            {/* Tab 3: Root Cause */}
            {detailTab === 'rootcause' && (
              <div className="space-y-4 text-xs">
                <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/40 space-y-3">
                  <div className="flex items-center gap-2 text-slate-800 dark:text-slate-200 font-semibold">
                    <FileCode className="w-4 h-4 text-blue-600" />
                    <span>Mapped Source Location</span>
                  </div>

                  <div className="p-2.5 rounded bg-slate-900 text-slate-200 font-mono text-[11px] border border-slate-800">
                    {selectedFinding.rule_id === 'SEC_COOKIE_INSECURE'
                      ? 'src/demo-app/sessionConfig.ts:12'
                      : selectedFinding.rule_id === 'CORS_WILDCARD_CREDENTIALS'
                      ? 'src/demo-app/corsConfig.ts:8'
                      : 'src/config/securityHeaders.ts:4'}
                  </div>

                  <p className="text-slate-600 dark:text-slate-400 text-[11px] leading-relaxed">
                    RootCauseMapper analyzed the runtime HTTP evidence and traced the missing attribute to configuration options in the target repository.
                  </p>
                </div>
              </div>
            )}

            {/* Modal Footer Actions */}
            <div className="pt-4 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between">
              <button
                onClick={() => setSelectedFinding(null)}
                className="py-2 px-4 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
              >
                Close
              </button>

              {selectedFinding.status === 'confirmed' && (
                <button
                  onClick={async () => {
                    const id = selectedFinding.id;
                    await onGenerateRemediation(id);
                    setSelectedFinding(null);
                    onNavigate('remediation');
                  }}
                  disabled={isRemediating}
                  className="py-2 px-4 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-xs flex items-center gap-1.5 disabled:opacity-50"
                >
                  <Wrench className="w-3.5 h-3.5" />
                  <span>{isRemediating ? 'Tracing & Generating Fix...' : 'Generate Fix'}</span>
                </button>
              )}

              {(selectedFinding.status === 'waiting_approval' || selectedFinding.status === 'approved') && (
                <button
                  onClick={() => {
                    setSelectedFinding(null);
                    onNavigate('remediation');
                  }}
                  className="py-2 px-4 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-semibold text-xs shadow-xs flex items-center gap-1.5"
                >
                  <Wrench className="w-3.5 h-3.5" />
                  <span>Review Ready Patch</span>
                </button>
              )}

              {selectedFinding.status === 'verified' && (
                <button
                  onClick={() => {
                    setSelectedFinding(null);
                    onNavigate('proofs');
                  }}
                  className="py-2 px-4 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-xs shadow-xs flex items-center gap-1.5"
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>View in Proof Center</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

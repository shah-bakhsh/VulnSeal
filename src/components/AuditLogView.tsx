import React, { useState } from 'react';
import type { AuditLog } from '../types/client';
import { FileText, CheckCircle, XCircle, X, Search, Shield, Lock } from 'lucide-react';

interface AuditLogViewProps {
  logs: AuditLog[];
}

export const AuditLogView: React.FC<AuditLogViewProps> = ({ logs }) => {
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredLogs = logs.filter((log) => {
    if (filterCategory === 'authorization' && !log.action.includes('AUTH') && !log.action.includes('TARGET')) return false;
    if (filterCategory === 'scan' && !log.action.includes('SCAN')) return false;
    if (filterCategory === 'policy' && !log.action.includes('POLICY') && !log.action.includes('SSRF') && log.actor !== 'NetworkGuard') return false;
    if (filterCategory === 'remediation' && !log.action.includes('PATCH') && !log.action.includes('REMEDIATION')) return false;
    if (filterCategory === 'verification' && !log.action.includes('PROOF') && !log.action.includes('VERIF')) return false;

    if (
      searchQuery &&
      !log.action.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !log.actor.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !log.resource_id.toLowerCase().includes(searchQuery.toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  const getResultBadge = (decision?: string) => {
    if (!decision) return <span className="font-mono text-slate-400">—</span>;
    const d = decision.toUpperCase();
    if (d === 'ALLOWED' || d === 'APPROVED' || d === 'VERIFIED' || d === 'SUCCEEDED') {
      return (
        <span className="inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-emerald-600 dark:text-emerald-400">
          <CheckCircle className="w-3 h-3" />
          <span>{d}</span>
        </span>
      );
    }
    if (d === 'DENIED' || d === 'REJECTED' || d === 'BLOCKED' || d === 'FAILED') {
      return (
        <span className="inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-red-600 dark:text-red-400">
          <XCircle className="w-3 h-3" />
          <span>{d}</span>
        </span>
      );
    }
    return <span className="font-mono text-[11px] text-slate-500 font-semibold">{d}</span>;
  };

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Page H1 Header and Filter */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-100 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
            Audit Log
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Chronological record of authorization, policy decisions, operator approvals, and verifications.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search audit records..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-white placeholder-slate-400 w-40 sm:w-48 focus:outline-hidden focus:border-blue-500"
            />
          </div>

          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-white font-medium"
          >
            <option value="all">All Events</option>
            <option value="authorization">Authorization</option>
            <option value="scan">Scans</option>
            <option value="policy">Policy &amp; SSRF</option>
            <option value="remediation">Approvals &amp; Fixes</option>
            <option value="verification">Verification &amp; Proofs</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-2xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200/80 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 text-slate-500 dark:text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Event Action</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Result</th>
                <th className="py-3 px-4">Resource</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
              {filteredLogs.map((log) => (
                <tr
                  key={log.id}
                  onClick={() => setSelectedLog(log)}
                  className="hover:bg-slate-50/60 dark:hover:bg-slate-800/40 cursor-pointer transition-colors"
                >
                  <td className="py-3.5 px-4 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </td>

                  <td className="py-3.5 px-4 font-mono font-medium text-slate-900 dark:text-white">
                    {log.action}
                  </td>

                  <td className="py-3.5 px-4 text-slate-600 dark:text-slate-300 font-medium">
                    {log.actor}
                  </td>

                  <td className="py-3.5 px-4">
                    {getResultBadge(log.decision)}
                  </td>

                  <td className="py-3.5 px-4 font-mono text-[11px] text-slate-500 truncate max-w-xs">
                    {log.resource_type}: {log.resource_id}
                  </td>

                  <td className="py-3.5 px-4 text-right">
                    <span className="text-xs text-blue-600 dark:text-blue-400 font-medium hover:underline">
                      Inspect →
                    </span>
                  </td>
                </tr>
              ))}

              {filteredLogs.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-xs text-slate-500 space-y-2">
                    <FileText className="w-8 h-8 text-slate-300 dark:text-slate-600 mx-auto" />
                    <p className="font-semibold text-slate-700 dark:text-slate-300">No audit logs found</p>
                    <p className="text-[11px] text-slate-400">Policy decisions and authorizations are logged here automatically.</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Audit Detail Drawer */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-end bg-slate-950/40 backdrop-blur-xs">
          <div className="w-full max-w-md h-full bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 p-6 shadow-2xl flex flex-col justify-between overflow-y-auto animate-in slide-in-from-right duration-200">
            <div className="space-y-4">
              <div className="flex items-start justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
                <div>
                  <span className="text-[11px] font-mono text-slate-400">AUDIT RECORD</span>
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white font-mono">
                    {selectedLog.action}
                  </h3>
                </div>
                <button
                  onClick={() => setSelectedLog(null)}
                  className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-2 p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 text-[11px] font-mono">
                  <div>
                    <span className="text-slate-400 block">RESULT</span>
                    <strong className="text-slate-900 dark:text-white">{selectedLog.decision}</strong>
                  </div>
                  <div>
                    <span className="text-slate-400 block">ACTOR</span>
                    <strong className="text-slate-900 dark:text-white truncate block">{selectedLog.actor}</strong>
                  </div>
                </div>

                <div>
                  <span className="text-slate-400 block text-[11px]">Timestamp</span>
                  <span className="font-mono text-slate-800 dark:text-slate-200 text-xs">
                    {new Date(selectedLog.timestamp).toLocaleString()}
                  </span>
                </div>

                <div>
                  <span className="text-slate-400 block text-[11px]">Resource Reference</span>
                  <div className="font-mono text-slate-800 dark:text-slate-200 text-xs break-all bg-slate-50 dark:bg-slate-800/60 p-2.5 rounded-lg border border-slate-100 dark:border-slate-800">
                    {selectedLog.resource_type}: {selectedLog.resource_id}
                  </div>
                </div>

                {selectedLog.details && (
                  <div>
                    <span className="text-slate-400 block text-[11px] mb-1">Structured Details</span>
                    <pre className="p-3 rounded-lg bg-slate-950 text-slate-200 font-mono text-[11px] overflow-x-auto border border-slate-800">
                      {JSON.stringify(selectedLog.details, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>

            <div className="pt-4 border-t border-slate-100 dark:border-slate-800">
              <button
                onClick={() => setSelectedLog(null)}
                className="w-full py-2 px-3 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
              >
                Close Record
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

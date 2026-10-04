import React, { useState } from 'react';
import type { ScanRun, Target, AgentEvent } from '../types/client';
import { StatusBadge } from './StatusBadge';
import {
  Radar,
  Play,
  CheckCircle2,
  Sliders,
  Shield,
  Clock,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  Layers,
  FileCheck,
  Check,
  XCircle,
} from 'lucide-react';

interface ScansViewProps {
  scans: ScanRun[];
  targets: Target[];
  agentEvents: AgentEvent[];
  onStartScan: (targetId: string) => Promise<void>;
  onRefresh: () => Promise<void>;
  isScanning: boolean;
}

export const ScansView: React.FC<ScansViewProps> = ({
  scans,
  targets,
  agentEvents,
  onStartScan,
  onRefresh,
  isScanning,
}) => {
  const [selectedTargetId, setSelectedTargetId] = useState<string>(
    targets[0]?.id || ''
  );
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [showScopeSettings, setShowScopeSettings] = useState<boolean>(false);
  const [requestBudget, setRequestBudget] = useState<number>(30);
  const [rateLimit, setRateLimit] = useState<number>(5);
  const [activeTesting, setActiveTesting] = useState<boolean>(true);
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({});

  const activeScan =
    scans.find(
      (s) =>
        s.status === 'scanning' ||
        s.status === 'discovering' ||
        s.status === 'authorizing' ||
        s.status === 'triaging'
    ) || (selectedScanId ? scans.find((s) => s.id === selectedScanId) : scans[0]);

  // Filter agent events associated with the active scan
  const activeEvents = activeScan
    ? agentEvents.filter((e) => e.scan_id === activeScan.id || (!e.scan_id && !e.finding_id))
    : agentEvents;

  // Group repetitive events (e.g. repetitive NetworkGuard blocks)
  const groupedEvents: {
    key: string;
    agent: string;
    title: string;
    count: number;
    events: AgentEvent[];
    status: string;
    latestTime: string;
  }[] = [];

  for (const evt of activeEvents) {
    if (evt.agent === 'PolicyEngine' && evt.message.includes('NetworkGuard blocked')) {
      const existing = groupedEvents.find((g) => g.key === 'networkguard_blocks');
      if (existing) {
        existing.count++;
        existing.events.push(evt);
      } else {
        groupedEvents.push({
          key: 'networkguard_blocks',
          agent: 'PolicyEngine',
          title: 'NetworkGuard SSRF Safeguard Policy Decisions',
          count: 1,
          events: [evt],
          status: 'warning',
          latestTime: evt.created_at,
        });
      }
    } else {
      groupedEvents.push({
        key: evt.id,
        agent: evt.agent,
        title: evt.message,
        count: 1,
        events: [evt],
        status: evt.status,
        latestTime: evt.created_at,
      });
    }
  }

  // Calculate pipeline stages for active scan
  const getPipelineStages = (scan: ScanRun) => {
    const isCompleted = scan.status === 'completed' || scan.status === 'completed_with_warnings';
    const isBlocked = scan.status === 'blocked';
    const isFailed = scan.status === 'failed';

    return [
      {
        id: 'auth',
        label: 'Authorization',
        agent: 'ScopeGuard',
        status: scan.status === 'authorizing' ? 'running' : 'completed',
        detail: 'Scope validated',
      },
      {
        id: 'mapping',
        label: 'Surface Mapping',
        agent: 'SurfaceMapper',
        status:
          scan.status === 'authorizing'
            ? 'pending'
            : scan.status === 'discovering'
            ? 'running'
            : 'completed',
        detail: `${scan.pages_discovered || 0} endpoints`,
      },
      {
        id: 'inspecting',
        label: 'Security Inspection',
        agent: 'SecurityInspector',
        status:
          scan.status === 'authorizing' || scan.status === 'discovering'
            ? 'pending'
            : scan.status === 'scanning'
            ? 'running'
            : 'completed',
        detail: `${scan.rules_executed || 0} rules`,
      },
      {
        id: 'triaging',
        label: 'Evidence Validation',
        agent: 'EvidenceJudge',
        status:
          scan.status === 'triaging'
            ? 'running'
            : isCompleted || isBlocked || isFailed
            ? 'completed'
            : 'pending',
        detail: `${scan.confirmed_findings_count || 0} confirmed`,
      },
      {
        id: 'terminal',
        label: isBlocked ? 'Blocked by Policy' : isFailed ? 'Failed' : 'Complete',
        agent: 'System',
        status: isBlocked ? 'failed' : isFailed ? 'failed' : isCompleted ? 'completed' : 'pending',
        detail: isBlocked ? 'Safety check' : isCompleted ? 'Ready' : 'Pending',
      },
    ];
  };

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Header and Trigger */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-100 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
            Scans
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Deterministic security scans executed within authorized ScopeGuard boundaries.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={selectedTargetId}
            onChange={(e) => setSelectedTargetId(e.target.value)}
            className="px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-white font-medium"
          >
            {targets.map((t) => (
              <option key={t.id} value={t.id} disabled={t.status !== 'authorized'}>
                {t.name} {t.status !== 'authorized' ? '(Unauthorized)' : ''}
              </option>
            ))}
          </select>

          <button
            type="button"
            onClick={() => setShowScopeSettings(!showScopeSettings)}
            className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors shadow-2xs"
            title="Configure scan scope, request budget, and rate limit"
          >
            <Sliders className="w-4 h-4" />
          </button>

          <button
            onClick={() => onStartScan(selectedTargetId)}
            disabled={isScanning || !selectedTargetId}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition-colors disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{isScanning ? 'Scan Running...' : 'Launch Scan'}</span>
          </button>
        </div>
      </div>

      {/* Scope Configuration Panel */}
      {showScopeSettings && (
        <div className="p-4 rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 space-y-4 shadow-2xs animate-in fade-in">
          <div className="flex items-center gap-2 pb-2 border-b border-slate-100 dark:border-slate-800">
            <Shield className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <h3 className="text-xs font-bold text-slate-900 dark:text-white">
              ScopeGuard Network Policy & Rate Budget Parameters
            </h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
            <div>
              <label className="block text-slate-600 dark:text-slate-400 mb-1">
                Request Budget ({requestBudget} requests max)
              </label>
              <input
                type="range"
                min="10"
                max="100"
                step="5"
                value={requestBudget}
                onChange={(e) => setRequestBudget(parseInt(e.target.value, 10))}
                className="w-full accent-blue-600"
              />
              <span className="text-[11px] font-mono text-slate-400">
                NetworkGuard terminates crawl if budget is reached.
              </span>
            </div>

            <div>
              <label className="block text-slate-600 dark:text-slate-400 mb-1">
                Rate Limit ({rateLimit} req / sec)
              </label>
              <input
                type="range"
                min="1"
                max="20"
                step="1"
                value={rateLimit}
                onChange={(e) => setRateLimit(parseInt(e.target.value, 10))}
                className="w-full accent-blue-600"
              />
              <span className="text-[11px] font-mono text-slate-400">
                Token bucket throttle protects target infrastructure.
              </span>
            </div>

            <div className="flex flex-col justify-center">
              <label className="inline-flex items-center gap-2 text-slate-700 dark:text-slate-300 font-medium cursor-pointer">
                <input
                  type="checkbox"
                  checked={activeTesting}
                  onChange={(e) => setActiveTesting(e.target.checked)}
                  className="rounded text-blue-600 focus:ring-blue-500"
                />
                <span>Active Testing Permitted</span>
              </label>
              <span className="text-[11px] font-mono text-slate-400 mt-1">
                Allows sending authenticated test probes.
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Active Scan Investigation Workspace */}
      {activeScan && (
        <div className="rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-5 shadow-2xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-lg bg-blue-50 dark:bg-blue-950/60 flex items-center justify-center text-blue-600 shrink-0">
                <Radar className={`w-4 h-4 ${activeScan.status === 'scanning' || activeScan.status === 'discovering' ? 'animate-spin' : ''}`} />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white truncate">
                    Investigation: {activeScan.target_url}
                  </h3>
                  <StatusBadge status={activeScan.status} />
                </div>
                <div className="text-[11px] font-mono text-slate-400 mt-0.5 truncate">
                  Scan ID: {activeScan.id}
                </div>
              </div>
            </div>

            <div className="text-right text-[11px] font-mono text-slate-400 shrink-0">
              Started: {new Date(activeScan.started_at).toLocaleTimeString()}
              {activeScan.duration_ms && ` · ${(activeScan.duration_ms / 1000).toFixed(1)}s`}
            </div>
          </div>

          {/* Stage Pipeline */}
          <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950/40 border border-slate-100 dark:border-slate-800">
            <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-2.5 font-semibold">
              Autonomous Pipeline Execution
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
              {getPipelineStages(activeScan).map((stage, idx) => (
                <div
                  key={stage.id}
                  className={`p-2.5 rounded-lg border text-xs space-y-1 ${
                    stage.status === 'completed'
                      ? 'border-emerald-200 dark:border-emerald-900/60 bg-emerald-50/40 dark:bg-emerald-950/20 text-emerald-800 dark:text-emerald-300'
                      : stage.status === 'running'
                      ? 'border-blue-300 dark:border-blue-800 bg-blue-50/60 dark:bg-blue-950/40 text-blue-800 dark:text-blue-300 animate-pulse'
                      : stage.status === 'failed'
                      ? 'border-red-200 dark:border-red-900/60 bg-red-50/40 dark:bg-red-950/20 text-red-800 dark:text-red-300'
                      : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-400'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] font-semibold">
                    <span>{idx + 1}. {stage.label}</span>
                    {stage.status === 'completed' && <Check className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />}
                    {stage.status === 'running' && <span className="w-2 h-2 rounded-full bg-blue-600 animate-ping" />}
                    {stage.status === 'failed' && <XCircle className="w-3.5 h-3.5 text-red-600" />}
                  </div>
                  <div className="text-[10px] font-mono opacity-80 truncate">
                    {stage.detail}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* LEFT Column: Investigation Metrics */}
            <div className="lg:col-span-6 space-y-3">
              <span className="text-xs font-bold text-slate-900 dark:text-white block">
                Investigation Metrics
              </span>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded-lg border border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/40 space-y-0.5">
                  <span className="text-[11px] text-slate-400">Pages Crawled</span>
                  <div className="text-lg font-bold font-mono text-slate-900 dark:text-white">
                    {activeScan.pages_discovered}
                  </div>
                </div>

                <div className="p-3 rounded-lg border border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/40 space-y-0.5">
                  <span className="text-[11px] text-slate-400">Rules Executed</span>
                  <div className="text-lg font-bold font-mono text-slate-900 dark:text-white">
                    {activeScan.rules_executed}
                  </div>
                </div>

                <div className="p-3 rounded-lg border border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/40 space-y-0.5">
                  <span className="text-[11px] text-slate-400">Confirmed Findings</span>
                  <div className="text-lg font-bold font-mono text-amber-600 dark:text-amber-400">
                    {activeScan.confirmed_findings_count}
                  </div>
                </div>

                <div className="p-3 rounded-lg border border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/40 space-y-0.5">
                  <span className="text-[11px] text-slate-400">HTTP Requests Made</span>
                  <div className="text-lg font-bold font-mono text-slate-900 dark:text-white">
                    {activeScan.requests_made}
                  </div>
                </div>
              </div>

              {activeScan.error_message && (
                <div className="p-3 rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50/40 dark:bg-red-950/20 text-xs text-red-700 dark:text-red-300 space-y-1">
                  <span className="font-semibold block">Safety Policy Decision:</span>
                  <p className="text-[11px] leading-relaxed">{activeScan.error_message}</p>
                </div>
              )}
            </div>

            {/* RIGHT Column: Agent Timeline */}
            <div className="lg:col-span-6 space-y-3">
              <span className="text-xs font-bold text-slate-900 dark:text-white block">
                Agent Timeline & Evidence Journal
              </span>

              <div className="max-h-72 overflow-y-auto space-y-2 pr-1">
                {groupedEvents.map((group) => {
                  const isExpanded = expandedGroups[group.key];
                  return (
                    <div
                      key={group.key}
                      className="p-2.5 rounded-lg border border-slate-100 dark:border-slate-800/80 bg-slate-50/40 dark:bg-slate-950/30 text-xs space-y-1"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-start gap-2 min-w-0">
                          <span className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1.5 shrink-0" />
                          <div className="min-w-0">
                            <span className="font-bold text-slate-800 dark:text-slate-200">
                              {group.agent}
                            </span>
                            <p className="text-slate-500 dark:text-slate-400 text-[11px] mt-0.5 leading-relaxed">
                              {group.title}
                            </p>
                          </div>
                        </div>
                        <span className="font-mono text-slate-400 text-[10px] shrink-0">
                          {new Date(group.latestTime).toLocaleTimeString()}
                        </span>
                      </div>

                      {group.count > 1 && (
                        <div className="pl-3.5 pt-1">
                          <button
                            type="button"
                            onClick={() =>
                              setExpandedGroups((prev) => ({ ...prev, [group.key]: !prev[group.key] }))
                            }
                            className="text-[10px] font-mono text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1"
                          >
                            <span>{isExpanded ? 'Hide' : `View ${group.count} individual events`}</span>
                            <ChevronDown className={`w-3 h-3 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                          </button>

                          {isExpanded && (
                            <div className="mt-1 space-y-1 pl-2 border-l border-slate-200 dark:border-slate-700 text-[10px] font-mono text-slate-500">
                              {group.events.map((ev) => (
                                <div key={ev.id} className="py-0.5">
                                  {ev.message}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}

                {groupedEvents.length === 0 && (
                  <div className="p-6 text-center text-xs text-slate-400">
                    No timeline events recorded yet.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Scans History Table */}
      <div className="rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden shadow-2xs">
        <div className="px-4 py-3 border-b border-slate-100 dark:border-slate-800 text-xs font-bold text-slate-900 dark:text-white">
          Scan History
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200/80 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 text-slate-500 dark:text-slate-400 font-medium">
                <th className="py-3 px-4">Scan Target</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Endpoints</th>
                <th className="py-3 px-4">Rules</th>
                <th className="py-3 px-4">Findings</th>
                <th className="py-3 px-4">Started</th>
                <th className="py-3 px-4 text-right">Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
              {scans.map((scan) => (
                <tr
                  key={scan.id}
                  onClick={() => setSelectedScanId(scan.id)}
                  className={`cursor-pointer transition-colors ${
                    activeScan?.id === scan.id
                      ? 'bg-blue-50/40 dark:bg-blue-950/20'
                      : 'hover:bg-slate-50/60 dark:hover:bg-slate-800/40'
                  }`}
                >
                  <td className="py-3 px-4 font-mono font-medium text-slate-900 dark:text-white truncate max-w-xs">
                    {scan.target_url}
                  </td>
                  <td className="py-3 px-4">
                    <StatusBadge status={scan.status} />
                  </td>
                  <td className="py-3 px-4 font-mono tabular-nums">{scan.pages_discovered}</td>
                  <td className="py-3 px-4 font-mono tabular-nums">{scan.rules_executed}</td>
                  <td className="py-3 px-4 font-mono tabular-nums font-semibold text-amber-600 dark:text-amber-400">
                    {scan.confirmed_findings_count}
                  </td>
                  <td className="py-3 px-4 text-slate-500 font-mono text-[11px]">
                    {new Date(scan.started_at).toLocaleTimeString()}
                  </td>
                  <td className="py-3 px-4 text-right font-mono text-slate-500 text-[11px]">
                    {scan.duration_ms ? `${(scan.duration_ms / 1000).toFixed(1)}s` : '—'}
                  </td>
                </tr>
              ))}

              {scans.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-xs text-slate-500">
                    No scans have been launched yet. Select an authorized target and click &quot;Launch Scan&quot;.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

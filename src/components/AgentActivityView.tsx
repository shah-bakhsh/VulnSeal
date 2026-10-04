import React, { useState } from 'react';
import type { AgentEvent } from '../types/client';
import {
  Activity,
  Shield,
  Radar,
  AlertCircle,
  Wrench,
  Cpu,
  ShieldCheck,
  X,
  Layers,
  Lock,
  Search,
} from 'lucide-react';

interface AgentActivityViewProps {
  events: AgentEvent[];
}

export const AgentActivityView: React.FC<AgentActivityViewProps> = ({ events }) => {
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [selectedEvent, setSelectedEvent] = useState<AgentEvent | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');

  const SEVEN_AGENTS = [
    'ScopeGuard',
    'SurfaceMapper',
    'SecurityInspector',
    'EvidenceJudge',
    'RootCauseMapper',
    'RemediationEngineer',
    'IndependentVerifier',
  ];

  const filteredEvents = events.filter((e) => {
    if (filterCategory === 'agents' && !SEVEN_AGENTS.includes(e.agent)) return false;
    if (filterCategory === 'policy' && e.agent !== 'PolicyEngine') return false;
    if (filterCategory === 'errors' && e.status !== 'error' && e.status !== 'warning') return false;
    if (
      filterCategory !== 'all' &&
      filterCategory !== 'agents' &&
      filterCategory !== 'policy' &&
      filterCategory !== 'errors' &&
      e.agent !== filterCategory
    ) {
      return false;
    }
    if (
      searchQuery &&
      !e.message.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !e.agent.toLowerCase().includes(searchQuery.toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  const getAgentIcon = (agent: string) => {
    switch (agent) {
      case 'ScopeGuard':
        return <Shield className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400" />;
      case 'PolicyEngine':
      case 'NetworkGuard':
        return <Lock className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />;
      case 'SurfaceMapper':
        return <Radar className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />;
      case 'SecurityInspector':
        return <AlertCircle className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />;
      case 'EvidenceJudge':
        return <ShieldCheck className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />;
      case 'RootCauseMapper':
      case 'RemediationEngineer':
        return <Wrench className="w-3.5 h-3.5 text-orange-600 dark:text-orange-400" />;
      case 'IndependentVerifier':
        return <Cpu className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />;
      default:
        return <Activity className="w-3.5 h-3.5 text-slate-500" />;
    }
  };

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Page H1 Header and Filter */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-100 dark:border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
            Agent Activity
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Real-time event journal from the 7 specialized VulnSeal agents and security policy engine.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search agent logs..."
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
            <option value="agents">All 7 AI Agents</option>
            <option value="policy">Policy &amp; Safety</option>
            <option value="errors">Errors &amp; Warnings</option>
            <optgroup label="Specific Agent">
              <option value="ScopeGuard">ScopeGuard</option>
              <option value="SurfaceMapper">SurfaceMapper</option>
              <option value="SecurityInspector">SecurityInspector</option>
              <option value="EvidenceJudge">EvidenceJudge</option>
              <option value="RootCauseMapper">RootCauseMapper</option>
              <option value="RemediationEngineer">RemediationEngineer</option>
              <option value="IndependentVerifier">IndependentVerifier</option>
            </optgroup>
          </select>
        </div>
      </div>

      {/* Events Timeline List */}
      <div className="rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-3 shadow-2xs">
        <div className="space-y-2">
          {filteredEvents.map((evt) => (
            <div
              key={evt.id}
              onClick={() => setSelectedEvent(evt)}
              className="flex items-start gap-3 p-3 rounded-lg border border-slate-100 dark:border-slate-800/80 hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition-colors cursor-pointer"
            >
              <div className="mt-0.5 shrink-0 p-1.5 rounded-md bg-slate-100 dark:bg-slate-800">
                {getAgentIcon(evt.agent)}
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-slate-900 dark:text-white">
                      {evt.agent}
                    </span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded uppercase ${
                      evt.status === 'success'
                        ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300'
                        : evt.status === 'error'
                        ? 'bg-red-50 dark:bg-red-950/60 text-red-700 dark:text-red-300'
                        : evt.status === 'warning'
                        ? 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-500'
                    }`}>
                      {evt.event_type}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-400 shrink-0">
                    {new Date(evt.created_at).toLocaleTimeString()}
                  </span>
                </div>

                <p className="text-xs text-slate-600 dark:text-slate-300 mt-1 leading-relaxed">
                  {evt.message}
                </p>
              </div>
            </div>
          ))}

          {filteredEvents.length === 0 && (
            <div className="py-12 text-center text-xs text-slate-500 space-y-2">
              <Activity className="w-8 h-8 text-slate-300 dark:text-slate-600 mx-auto" />
              <p className="font-medium text-slate-700 dark:text-slate-300">No events recorded</p>
              <p className="text-[11px] text-slate-400">Launch a scan to observe real agent orchestration.</p>
            </div>
          )}
        </div>
      </div>

      {/* Event Details Drawer */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-end bg-slate-950/40 backdrop-blur-xs">
          <div className="w-full max-w-md h-full bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 p-6 shadow-2xl flex flex-col justify-between overflow-y-auto animate-in slide-in-from-right duration-200">
            <div className="space-y-4">
              <div className="flex items-start justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded bg-slate-100 dark:bg-slate-800">
                    {getAgentIcon(selectedEvent.agent)}
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                      {selectedEvent.agent}
                    </h3>
                    <span className="text-[11px] font-mono text-slate-400">
                      ID: {selectedEvent.id}
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="p-1 rounded text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-3 text-xs">
                <div>
                  <span className="text-slate-400 block text-[11px]">Timestamp</span>
                  <span className="font-mono text-slate-800 dark:text-slate-200">
                    {new Date(selectedEvent.created_at).toLocaleString()}
                  </span>
                </div>

                <div>
                  <span className="text-slate-400 block text-[11px]">Message</span>
                  <p className="text-slate-800 dark:text-slate-200 mt-1 leading-relaxed bg-slate-50 dark:bg-slate-800/60 p-3 rounded-lg border border-slate-100 dark:border-slate-800">
                    {selectedEvent.message}
                  </p>
                </div>

                {selectedEvent.metadata && (
                  <div>
                    <span className="text-slate-400 block text-[11px] mb-1">Structured Metadata</span>
                    <pre className="p-3 rounded-lg bg-slate-950 text-slate-200 font-mono text-[11px] overflow-x-auto">
                      {JSON.stringify(selectedEvent.metadata, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>

            <div className="pt-4 border-t border-slate-100 dark:border-slate-800">
              <button
                onClick={() => setSelectedEvent(null)}
                className="w-full py-2 px-3 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

import React from 'react';
import type { FindingEvidence } from '../types/client';

interface HttpViewerProps {
  evidence: FindingEvidence;
  className?: string;
}

export const HttpViewer: React.FC<HttpViewerProps> = ({ evidence, className = '' }) => {
  return (
    <div className={`space-y-4 text-xs font-mono ${className}`}>
      {/* Request details */}
      <div className="rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 p-3">
        <div className="font-semibold text-slate-700 dark:text-slate-300 pb-1.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <span>HTTP Request Captured</span>
          <span className="text-slate-500 font-normal">{evidence.captured_at}</span>
        </div>
        <div className="pt-2 text-slate-800 dark:text-slate-200">
          <span className="font-bold text-blue-600 dark:text-blue-400">{evidence.request_method}</span>{' '}
          <span>{evidence.request_url}</span>
        </div>
        <div className="pt-2 text-slate-600 dark:text-slate-400 space-y-0.5">
          {Object.entries(evidence.request_headers || {}).map(([k, v]) => (
            <div key={k}>
              <span className="text-slate-500">{k}:</span> {v}
            </div>
          ))}
        </div>
      </div>

      {/* Response details */}
      <div className="rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 p-3">
        <div className="font-semibold text-slate-700 dark:text-slate-300 pb-1.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <span>HTTP Response Captured</span>
          <span className="font-bold text-amber-600 dark:text-amber-400">
            {evidence.response_status} {evidence.response_status_text}
          </span>
        </div>
        <div className="pt-2 space-y-1">
          {Object.entries(evidence.response_headers || {}).map(([k, v]) => {
            const isHighlight = k.toLowerCase() === 'set-cookie';
            return (
              <div
                key={k}
                className={
                  isHighlight
                    ? 'p-2 rounded bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 font-semibold text-amber-900 dark:text-amber-300'
                    : 'text-slate-600 dark:text-slate-400'
                }
              >
                <span className="text-slate-500 dark:text-slate-400 font-normal">{k}:</span> {v}
              </div>
            );
          })}
        </div>
      </div>

      {/* Observation Summary */}
      <div className="p-3 rounded border border-amber-200 dark:border-amber-900/50 bg-amber-50/50 dark:bg-amber-950/20 text-slate-800 dark:text-slate-200">
        <div className="font-semibold text-amber-800 dark:text-amber-400 mb-1 flex items-center gap-1.5">
          <span>Deterministic Observation</span>
        </div>
        <p className="text-xs leading-relaxed">{evidence.observation_description}</p>
        <div className="mt-2 pt-2 border-t border-amber-200 dark:border-amber-900/40 text-[11px] text-slate-500 dark:text-slate-400 flex items-center justify-between">
          <span>Evidence SHA-256: {evidence.sha256_hash.slice(0, 16)}...</span>
          {evidence.raw_attribute_missing && (
            <span className="font-medium text-red-600 dark:text-red-400">
              Missing Attribute: {evidence.raw_attribute_missing}
            </span>
          )}
        </div>
      </div>
    </div>
  );
};

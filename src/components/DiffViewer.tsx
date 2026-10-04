import React, { useState } from 'react';
import { Columns, AlignLeft } from 'lucide-react';

interface DiffViewerProps {
  diff: string;
  className?: string;
}

export const DiffViewer: React.FC<DiffViewerProps> = ({ diff, className = '' }) => {
  const [viewMode, setViewMode] = useState<'unified' | 'split'>('unified');

  const lines = diff.split('\n');

  // Compute split lines (before vs after)
  const leftLines: { text: string; type: 'normal' | 'deletion' | 'empty' | 'header' }[] = [];
  const rightLines: { text: string; type: 'normal' | 'addition' | 'empty' | 'header' }[] = [];

  lines.forEach((line) => {
    if (line.startsWith('+++') || line.startsWith('---') || line.startsWith('@@')) {
      leftLines.push({ text: line, type: 'header' });
      rightLines.push({ text: line, type: 'header' });
    } else if (line.startsWith('-')) {
      leftLines.push({ text: line.slice(1), type: 'deletion' });
    } else if (line.startsWith('+')) {
      rightLines.push({ text: line.slice(1), type: 'addition' });
    } else {
      const normalText = line.startsWith(' ') ? line.slice(1) : line;
      leftLines.push({ text: normalText, type: 'normal' });
      rightLines.push({ text: normalText, type: 'normal' });
    }
  });

  // Align lengths for split view
  const maxLen = Math.max(leftLines.length, rightLines.length);
  while (leftLines.length < maxLen) {
    leftLines.push({ text: '', type: 'empty' });
  }
  while (rightLines.length < maxLen) {
    rightLines.push({ text: '', type: 'empty' });
  }

  return (
    <div
      className={`overflow-hidden rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-950 font-mono text-xs text-slate-100 shadow-2xs ${className}`}
    >
      {/* Diff Header Bar with View Switcher */}
      <div className="px-4 py-2 border-b border-slate-800 bg-slate-900/80 text-slate-400 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-slate-300">Security Patch Diff</span>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
            git unified
          </span>
        </div>

        {/* Unified vs Split Toggle */}
        <div className="flex items-center gap-1 bg-slate-950 p-0.5 rounded-lg border border-slate-800 text-[11px]">
          <button
            type="button"
            onClick={() => setViewMode('unified')}
            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded transition-colors ${
              viewMode === 'unified'
                ? 'bg-blue-600 text-white font-medium'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <AlignLeft className="w-3 h-3" />
            <span>Unified</span>
          </button>
          <button
            type="button"
            onClick={() => setViewMode('split')}
            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded transition-colors ${
              viewMode === 'split'
                ? 'bg-blue-600 text-white font-medium'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Columns className="w-3 h-3" />
            <span>Split</span>
          </button>
        </div>
      </div>

      {viewMode === 'unified' ? (
        <pre className="p-3 leading-relaxed overflow-x-auto text-[11px] sm:text-xs">
          {lines.map((line, idx) => {
            let lineClass = 'text-slate-300';
            let bgClass = '';

            if (line.startsWith('+++') || line.startsWith('---')) {
              lineClass = 'text-slate-400 font-semibold';
            } else if (line.startsWith('@@')) {
              lineClass = 'text-cyan-400 font-medium';
              bgClass = 'bg-cyan-950/30';
            } else if (line.startsWith('+')) {
              lineClass = 'text-emerald-400';
              bgClass = 'bg-emerald-950/40';
            } else if (line.startsWith('-')) {
              lineClass = 'text-rose-400';
              bgClass = 'bg-rose-950/40';
            }

            return (
              <div
                key={idx}
                className={`px-2 py-0.5 rounded-sm flex items-start gap-3 ${bgClass}`}
              >
                <span className="w-6 shrink-0 text-right text-slate-600 select-none font-mono text-[11px]">
                  {idx + 1}
                </span>
                <span className={`flex-1 break-all ${lineClass}`}>{line || ' '}</span>
              </div>
            );
          })}
        </pre>
      ) : (
        /* Split (Side-by-Side) Mode */
        <div className="grid grid-cols-2 divide-x divide-slate-800 text-[11px] sm:text-xs overflow-x-auto">
          {/* Left Column: Original */}
          <div className="p-3 space-y-0.5">
            <div className="text-[10px] font-mono uppercase tracking-wider text-rose-400 pb-1 mb-1 border-b border-slate-800/80 font-bold">
              Original (Before)
            </div>
            {leftLines.map((item, idx) => (
              <div
                key={idx}
                className={`px-2 py-0.5 rounded-sm font-mono truncate ${
                  item.type === 'deletion'
                    ? 'bg-rose-950/50 text-rose-300'
                    : item.type === 'header'
                    ? 'text-cyan-400 font-semibold text-[10px]'
                    : 'text-slate-300'
                }`}
              >
                {item.text || ' '}
              </div>
            ))}
          </div>

          {/* Right Column: Remediated */}
          <div className="p-3 space-y-0.5">
            <div className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 pb-1 mb-1 border-b border-slate-800/80 font-bold">
              Remediated (After)
            </div>
            {rightLines.map((item, idx) => (
              <div
                key={idx}
                className={`px-2 py-0.5 rounded-sm font-mono truncate ${
                  item.type === 'addition'
                    ? 'bg-emerald-950/50 text-emerald-300'
                    : item.type === 'header'
                    ? 'text-cyan-400 font-semibold text-[10px]'
                    : 'text-slate-300'
                }`}
              >
                {item.text || ' '}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

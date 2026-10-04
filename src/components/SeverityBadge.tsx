import React from 'react';
import { AlertCircle, AlertTriangle, Info, ShieldAlert } from 'lucide-react';
import type { Severity } from '../types/client';

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className = '' }) => {
  switch (severity) {
    case 'critical':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-semibold text-red-700 dark:text-red-400 ${className}`}>
          <ShieldAlert className="w-3.5 h-3.5 text-red-600 dark:text-red-400 shrink-0" aria-hidden="true" />
          <span>Critical</span>
        </span>
      );
    case 'high':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-semibold text-amber-700 dark:text-amber-400 ${className}`}>
          <AlertCircle className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 shrink-0" aria-hidden="true" />
          <span>High</span>
        </span>
      );
    case 'medium':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-medium text-yellow-700 dark:text-yellow-400 ${className}`}>
          <AlertTriangle className="w-3.5 h-3.5 text-yellow-600 dark:text-yellow-400 shrink-0" aria-hidden="true" />
          <span>Medium</span>
        </span>
      );
    case 'low':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-medium text-blue-700 dark:text-blue-400 ${className}`}>
          <Info className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0" aria-hidden="true" />
          <span>Low</span>
        </span>
      );
    case 'info':
    default:
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 ${className}`}>
          <Info className="w-3.5 h-3.5 text-slate-500 shrink-0" aria-hidden="true" />
          <span>Info</span>
        </span>
      );
  }
};

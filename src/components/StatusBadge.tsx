import React from 'react';
import { CheckCircle2, Clock, XCircle, AlertCircle, ShieldCheck } from 'lucide-react';

interface StatusBadgeProps {
  status: string;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, className = '' }) => {
  switch (status) {
    case 'verified':
    case 'authorized':
    case 'completed':
    case 'approved':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-400 ${className}`}>
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" aria-hidden="true" />
          <span className="capitalize">{status.replace('_', ' ')}</span>
        </span>
      );
    case 'waiting_approval':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-medium text-amber-700 dark:text-amber-400 ${className}`}>
          <Clock className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 shrink-0 animate-pulse" aria-hidden="true" />
          <span>Waiting Approval</span>
        </span>
      );
    case 'confirmed':
    case 'remediation_ready':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-medium text-amber-700 dark:text-amber-400 ${className}`}>
          <AlertCircle className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 shrink-0" aria-hidden="true" />
          <span className="capitalize">{status.replace('_', ' ')}</span>
        </span>
      );
    case 'sandbox_testing':
    case 'verifying':
    case 'scanning':
    case 'discovering':
    case 'authorizing':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-medium text-blue-700 dark:text-blue-400 ${className}`}>
          <Clock className="w-3.5 h-3.5 text-blue-600 dark:text-blue-400 shrink-0 animate-spin" aria-hidden="true" />
          <span className="capitalize">{status.replace('_', ' ')}...</span>
        </span>
      );
    case 'failed':
    case 'failed_verification':
    case 'regression_detected':
    case 'unverified':
    case 'rejected':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-medium text-red-700 dark:text-red-400 ${className}`}>
          <XCircle className="w-3.5 h-3.5 text-red-600 dark:text-red-400 shrink-0" aria-hidden="true" />
          <span className="capitalize">{status.replace('_', ' ')}</span>
        </span>
      );
    case 'VERIFIED':
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700 dark:text-emerald-400 ${className}`}>
          <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" aria-hidden="true" />
          <span>VERIFIED FIX</span>
        </span>
      );
    default:
      return (
        <span className={`inline-flex items-center gap-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 ${className}`}>
          <Clock className="w-3.5 h-3.5 text-slate-500 shrink-0" aria-hidden="true" />
          <span className="capitalize">{status.replace('_', ' ')}</span>
        </span>
      );
  }
};

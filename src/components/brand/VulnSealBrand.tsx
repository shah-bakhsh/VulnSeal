import React from 'react';
import { VulnSealLogo, LogoSize } from './VulnSealLogo';

export interface VulnSealBrandProps {
  size?: 'sm' | 'md' | 'lg';
  collapsed?: boolean;
  showTagline?: boolean;
  className?: string;
  onClick?: () => void;
}

export const VulnSealBrand: React.FC<VulnSealBrandProps> = ({
  size = 'md',
  collapsed = false,
  showTagline = false,
  className = '',
  onClick,
}) => {
  const logoSize: LogoSize = size === 'sm' ? 'sm' : size === 'lg' ? 'lg' : 'md';

  if (collapsed) {
    return (
      <div
        className={`flex items-center justify-center w-full py-1 ${onClick ? 'cursor-pointer' : ''} ${className}`}
        onClick={onClick}
        title="VulnSeal — Autonomous Security Remediation"
      >
        <VulnSealLogo size={logoSize} />
      </div>
    );
  }

  const titleSizes = {
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-lg',
  };

  const taglineSizes = {
    sm: 'text-[9.5px]',
    md: 'text-[10.5px]',
    lg: 'text-xs',
  };

  return (
    <div
      className={`flex items-center gap-2.5 select-none ${onClick ? 'cursor-pointer group' : ''} ${className}`}
      onClick={onClick}
    >
      <VulnSealLogo size={logoSize} />
      <div className="flex flex-col min-w-0">
        <div className="flex items-center gap-1.5">
          <span className={`font-semibold tracking-tight text-slate-900 dark:text-white ${titleSizes[size]}`}>
            Vuln<span className="text-blue-600 dark:text-blue-400">Seal</span>
          </span>
          <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-medium border border-blue-500/20 bg-blue-50/60 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400">
            PRO
          </span>
        </div>
        {showTagline && (
          <span className={`font-medium text-slate-500 dark:text-slate-400 tracking-wide truncate ${taglineSizes[size]}`}>
            Find. Fix. Prove.
          </span>
        )}
      </div>
    </div>
  );
};

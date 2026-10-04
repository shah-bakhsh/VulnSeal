import React from 'react';

export type LogoSize = 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl' | number;

export interface VulnSealLogoProps {
  size?: LogoSize;
  className?: string;
  variant?: 'symbol' | 'full' | 'badge';
  showWordmark?: boolean;
  tagline?: boolean | string;
  onClick?: () => void;
}

const sizeMap: Record<string, { px: number; tw: string; textClass: string; taglineClass: string }> = {
  xs: { px: 20, tw: 'w-5 h-5', textClass: 'text-xs font-bold', taglineClass: 'text-[9px]' },
  sm: { px: 28, tw: 'w-7 h-7', textClass: 'text-sm font-bold', taglineClass: 'text-[10px]' },
  md: { px: 36, tw: 'w-9 h-9', textClass: 'text-base font-bold', taglineClass: 'text-xs' },
  lg: { px: 48, tw: 'w-12 h-12', textClass: 'text-xl font-bold tracking-tight', taglineClass: 'text-xs' },
  xl: { px: 68, tw: 'w-[68px] h-[68px]', textClass: 'text-2xl font-bold tracking-tight', taglineClass: 'text-sm' },
  '2xl': { px: 96, tw: 'w-24 h-24', textClass: 'text-3xl font-extrabold tracking-tight', taglineClass: 'text-sm' },
};

export const VulnSealLogo: React.FC<VulnSealLogoProps> = ({
  size = 'md',
  className = '',
  variant = 'symbol',
  showWordmark = false,
  tagline,
  onClick,
}) => {
  const sizeConfig = typeof size === 'string' && sizeMap[size]
    ? sizeMap[size]
    : {
        px: typeof size === 'number' ? size : 36,
        tw: '',
        textClass: 'text-base font-bold',
        taglineClass: 'text-xs',
      };

  const customStyle = typeof size === 'number'
    ? { width: `${size}px`, height: `${size}px` }
    : undefined;

  const logoImage = (
    <div
      className={`relative inline-flex items-center justify-center shrink-0 select-none ${sizeConfig.tw} ${className}`}
      style={customStyle}
      onClick={onClick}
    >
      <img
        src="/brand/vulnseal-logo.svg"
        alt="VulnSeal"
        className="w-full h-full object-contain filter drop-shadow-xs transition-transform duration-200 hover:scale-[1.02]"
        width={sizeConfig.px}
        height={sizeConfig.px}
        loading="eager"
        decoding="async"
        referrerPolicy="no-referrer"
        onError={(e) => {
          // Fallback to high-res PNG if SVG rendering fails in older browser
          const target = e.currentTarget;
          if (target.src.endsWith('.svg')) {
            target.src = '/brand/vulnseal-logo.png';
          }
        }}
      />
    </div>
  );

  if (!showWordmark) {
    return logoImage;
  }

  const taglineText = typeof tagline === 'string'
    ? tagline
    : 'Find. Fix. Prove.';

  return (
    <div
      className={`inline-flex items-center gap-2.5 ${onClick ? 'cursor-pointer' : ''}`}
      onClick={onClick}
    >
      {logoImage}
      <div className="flex flex-col leading-none">
        <span className={`text-slate-900 dark:text-white tracking-tight ${sizeConfig.textClass}`}>
          Vuln<span className="text-blue-600 dark:text-blue-400">Seal</span>
        </span>
        {tagline && (
          <span className={`text-slate-500 dark:text-slate-400 font-medium tracking-wide mt-0.5 ${sizeConfig.taglineClass}`}>
            {taglineText}
          </span>
        )}
      </div>
    </div>
  );
};

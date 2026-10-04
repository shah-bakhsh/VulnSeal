import React from 'react';

interface VulnSealLogoProps {
  className?: string;
  size?: number;
  showText?: boolean;
}

export const VulnSealLogo: React.FC<VulnSealLogoProps> = ({
  className = '',
  size = 28,
  showText = false,
}) => {
  return (
    <div className={`inline-flex items-center gap-2.5 ${className}`}>
      <div
        className="relative flex items-center justify-center shrink-0 rounded-lg shadow-sm overflow-hidden"
        style={{ width: size, height: size }}
      >
        <svg
          viewBox="0 0 32 32"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-full"
        >
          <defs>
            <linearGradient id="vs-shield-grad" x1="2" y1="2" x2="30" y2="30" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#2563EB" />
              <stop offset="50%" stopColor="#1D4ED8" />
              <stop offset="100%" stopColor="#0F172A" />
            </linearGradient>
            <linearGradient id="vs-accent-grad" x1="10" y1="8" x2="22" y2="24" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#38BDF8" />
              <stop offset="100%" stopColor="#6366F1" />
            </linearGradient>
            <filter id="vs-glow" x="-20%" y="-20%" width="140%" height="140%">
              <feDropShadow dx="0" dy="1" stdDeviation="1" floodColor="#38BDF8" floodOpacity="0.4" />
            </filter>
          </defs>

          {/* Outer Shield Container */}
          <path
            d="M16 2.5L28 6.8V14.5C28 22.2 22.9 28.2 16 30C9.1 28.2 4 22.2 4 14.5V6.8L16 2.5Z"
            fill="url(#vs-shield-grad)"
          />

          {/* Shield Border Accent */}
          <path
            d="M16 3.5L27 7.4V14.5C27 21.6 22.3 27.2 16 28.9C9.7 27.2 5 21.6 5 14.5V7.4L16 3.5Z"
            stroke="url(#vs-accent-grad)"
            strokeWidth="1.2"
            strokeOpacity="0.8"
            fill="none"
          />

          {/* Inner Cryptographic Seal / Keyhole Geometry */}
          {/* Shackle */}
          <path
            d="M12.5 14.5V11.5C12.5 9.57 14.07 8 16 8C17.93 8 19.5 9.57 19.5 11.5V14.5"
            stroke="#FFFFFF"
            strokeWidth="1.8"
            strokeLinecap="round"
            fill="none"
          />

          {/* Padlock / Seal Core Base */}
          <rect
            x="10.5"
            y="14"
            width="11"
            height="9"
            rx="2"
            fill="url(#vs-accent-grad)"
            filter="url(#vs-glow)"
          />

          {/* Keyhole Core */}
          <circle cx="16" cy="17.2" r="1.3" fill="#FFFFFF" />
          <path
            d="M15.4 18L15.1 20.8C15.1 21.2 15.4 21.5 16 21.5C16.6 21.5 16.9 21.2 16.9 20.8L16.6 18H15.4Z"
            fill="#FFFFFF"
          />

          {/* Verification Pulse Dot */}
          <circle cx="23" cy="7" r="1.5" fill="#34D399" />
        </svg>
      </div>

      {showText && (
        <div className="flex flex-col min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="text-sm font-extrabold tracking-tight text-slate-900 dark:text-white">
              Vuln<span className="text-blue-600 dark:text-blue-400">Seal</span>
            </span>
            <span className="text-[9px] font-mono font-semibold uppercase px-1 py-0.2 rounded bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800">
              v2.4
            </span>
          </div>
          <span className="text-[10px] text-slate-400 dark:text-slate-500 font-medium truncate">
            Autonomous Defense Platform
          </span>
        </div>
      )}
    </div>
  );
};

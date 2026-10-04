import React, { useEffect, useState } from 'react';
import { Sun, Moon, Menu, Search, User, Shield, Terminal } from 'lucide-react';
import { NavItem } from './Navigation';
import { VulnSealLogo } from './brand/VulnSealLogo';

interface HeaderProps {
  currentTab: NavItem;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
  onOpenMobileNav: () => void;
  onOpenCommandPalette: () => void;
  onOpenAuth?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentTab,
  theme,
  onToggleTheme,
  onOpenMobileNav,
  onOpenCommandPalette,
  onOpenAuth,
}) => {
  const [isMac, setIsMac] = useState(true);

  useEffect(() => {
    if (typeof window !== 'undefined' && navigator?.userAgent) {
      setIsMac(/(Mac|iPhone|iPod|iPad)/i.test(navigator.userAgent));
    }
  }, []);

  const isDemo = currentTab === 'demo';

  return (
    <header className="h-14 px-4 sm:px-6 border-b border-slate-200 dark:border-slate-800/80 bg-white/95 dark:bg-slate-900/95 backdrop-blur-md sticky top-0 z-30 flex items-center justify-between">
      {/* Left: Mobile Toggle & Workspace Context */}
      <div className="flex items-center gap-3">
        <button
          onClick={onOpenMobileNav}
          className="p-1.5 rounded-md text-slate-500 hover:text-slate-900 dark:hover:text-white lg:hidden"
          aria-label="Open navigation menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2 lg:hidden">
          <VulnSealLogo size="xs" />
        </div>

        {/* Global Workspace Indicator */}
        <div className="hidden sm:flex items-center gap-2 text-xs">
          {isDemo ? (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-amber-50 dark:bg-amber-950/50 border border-amber-200 dark:border-amber-900 text-amber-800 dark:text-amber-300 font-medium">
              <Terminal className="w-3.5 h-3.5" />
              <span>Demo Lab Sandbox</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400">
              <span className="font-semibold text-slate-700 dark:text-slate-200">Production Workspace</span>
              <span>/</span>
              <span className="text-slate-400 dark:text-slate-500 font-mono text-[11px]">Primary</span>
            </div>
          )}
        </div>
      </div>

      {/* Middle: Fast Search Trigger for Command Palette */}
      <div className="hidden sm:flex items-center flex-1 max-w-md mx-6">
        <button
          type="button"
          onClick={onOpenCommandPalette}
          className="w-full flex items-center justify-between px-3.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-950/40 text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:border-slate-300 dark:hover:border-slate-700 transition-colors shadow-2xs"
        >
          <div className="flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-slate-400" />
            <span>Search targets, findings, or run actions...</span>
          </div>
          <kbd className="px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 font-mono text-[10px] text-slate-500">
            {isMac ? '⌘K' : 'Ctrl+K'}
          </kbd>
        </button>
      </div>

      {/* Right: Search Mobile + Theme Toggle + User Avatar */}
      <div className="flex items-center gap-2.5">
        <button
          type="button"
          onClick={onOpenCommandPalette}
          className="p-1.5 rounded-lg text-slate-500 hover:text-slate-900 dark:hover:text-white sm:hidden"
          aria-label="Open search command palette"
        >
          <Search className="w-4 h-4" />
        </button>

        {/* Segmented Light / Dark Theme Controller */}
        <div className="flex items-center p-0.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-100/90 dark:bg-slate-800/90 text-xs">
          <button
            type="button"
            onClick={() => theme !== 'light' && onToggleTheme()}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md transition-all font-medium ${
              theme === 'light'
                ? 'bg-white text-slate-900 shadow-xs font-semibold'
                : 'text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
            }`}
            title="Switch to Light mode"
            aria-label="Light mode"
          >
            <Sun className="w-3.5 h-3.5 text-amber-500" />
            <span className="hidden md:inline">Light</span>
          </button>
          <button
            type="button"
            onClick={() => theme !== 'dark' && onToggleTheme()}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md transition-all font-medium ${
              theme === 'dark'
                ? 'bg-slate-900 text-white shadow-xs font-semibold'
                : 'text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
            }`}
            title="Switch to Dark mode"
            aria-label="Dark mode"
          >
            <Moon className="w-3.5 h-3.5 text-blue-400" />
            <span className="hidden md:inline">Dark</span>
          </button>
        </div>

        {/* User Identity & Auth Switcher */}
        <button
          type="button"
          onClick={onOpenAuth}
          className="flex items-center gap-2 pl-2 border-l border-slate-200 dark:border-slate-800 hover:opacity-80 transition-opacity text-left cursor-pointer"
          title="Operator Session / Switch Account"
          aria-label="Open Operator Session and Brand Profile"
        >
          <div className="w-7 h-7 rounded-full bg-blue-100 dark:bg-blue-950/80 border border-blue-200 dark:border-blue-800 flex items-center justify-center text-blue-700 dark:text-blue-300 text-xs font-semibold shrink-0">
            <User className="w-3.5 h-3.5" />
          </div>
          <div className="hidden lg:block text-left">
            <div className="text-xs font-semibold text-slate-900 dark:text-white leading-tight">
              Security Engineer
            </div>
            <div className="text-[10px] text-slate-400 font-mono">
              Authorized Operator
            </div>
          </div>
        </button>
      </div>
    </header>
  );
};

import React, { useState } from 'react';
import {
  LayoutDashboard,
  Target,
  Radar,
  ShieldAlert,
  Wrench,
  ShieldCheck,
  Activity,
  FileText,
  Terminal,
  ChevronDown,
  ChevronsLeft,
  ChevronsRight,
  Shield,
  HelpCircle,
  Settings as SettingsIcon,
} from 'lucide-react';
import { VulnSealLogo } from './brand/VulnSealLogo';

export type NavItem =
  | 'overview'
  | 'targets'
  | 'scans'
  | 'findings'
  | 'remediation'
  | 'shadowfix'
  | 'proofs'
  | 'agents'
  | 'audit'
  | 'demo'
  | 'settings';

interface NavigationProps {
  currentTab: NavItem;
  onTabChange: (tab: NavItem) => void;
  openFindingsCount?: number;
  verifiedFixesCount?: number;
  mobileOpen: boolean;
  onCloseMobile: () => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
}

export const Navigation: React.FC<NavigationProps> = ({
  currentTab,
  onTabChange,
  openFindingsCount = 0,
  verifiedFixesCount = 0,
  mobileOpen,
  onCloseMobile,
  collapsed,
  onToggleCollapse,
}) => {
  const [workspaceMenuOpen, setWorkspaceMenuOpen] = useState(false);

  // Grouped navigation structure
  const primarySection: { id: NavItem; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  ];

  const securitySection: { id: NavItem; label: string; icon: React.ComponentType<{ className?: string }>; count?: number }[] = [
    { id: 'targets', label: 'Targets', icon: Target },
    { id: 'scans', label: 'Scans', icon: Radar },
    { id: 'findings', label: 'Findings', icon: ShieldAlert, count: openFindingsCount },
  ];

  const remediationSection: { id: NavItem; label: string; icon: React.ComponentType<{ className?: string }>; count?: number }[] = [
    { id: 'remediation', label: 'Fixes', icon: Wrench },
    { id: 'proofs', label: 'Proof Center', icon: ShieldCheck, count: verifiedFixesCount },
  ];

  const activitySection: { id: NavItem; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { id: 'agents', label: 'Agent Activity', icon: Activity },
    { id: 'audit', label: 'Audit Log', icon: FileText },
  ];

  const bottomSection: { id: NavItem; label: string; icon: React.ComponentType<{ className?: string }>; badge?: string }[] = [
    { id: 'demo', label: 'Demo Lab', icon: Terminal, badge: 'Lab' },
  ];

  const renderNavButton = (item: {
    id: NavItem;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    count?: number;
    badge?: string;
  }) => {
    const Icon = item.icon;
    const isActive = currentTab === item.id;

    return (
      <button
        key={item.id}
        onClick={() => {
          onTabChange(item.id);
          onCloseMobile();
        }}
        title={collapsed ? item.label : undefined}
        className={`w-full flex items-center ${
          collapsed ? 'justify-center px-2' : 'justify-between px-3'
        } py-2 rounded-lg text-xs font-medium transition-colors ${
          isActive
            ? 'bg-blue-50 dark:bg-blue-950/50 text-blue-700 dark:text-blue-400 font-semibold'
            : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100/60 dark:hover:bg-slate-800/40'
        }`}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <Icon
            className={`w-4 h-4 shrink-0 transition-colors ${
              isActive ? 'text-blue-600 dark:text-blue-400' : 'text-slate-400 dark:text-slate-500'
            }`}
          />
          {!collapsed && <span className="truncate">{item.label}</span>}
        </div>

        {!collapsed && item.count !== undefined && item.count > 0 && (
          <span
            className={`text-[10px] font-mono tabular-nums px-1.5 py-0.5 rounded-full ${
              isActive
                ? 'bg-blue-200/80 dark:bg-blue-900/80 text-blue-900 dark:text-blue-200'
                : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
            }`}
          >
            {item.count}
          </span>
        )}

        {!collapsed && item.badge && (
          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-amber-50 dark:bg-amber-950/50 text-amber-700 dark:text-amber-400 border border-amber-200/60 dark:border-amber-900/60">
            {item.badge}
          </span>
        )}
      </button>
    );
  };

  return (
    <>
      {/* Mobile backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-slate-950/40 backdrop-blur-xs z-40 lg:hidden"
          onClick={onCloseMobile}
        />
      )}

      <aside
        className={`fixed lg:static top-0 bottom-0 left-0 z-50 border-r border-slate-200 dark:border-slate-800/80 bg-white dark:bg-slate-900/95 flex flex-col justify-between transition-all duration-200 ease-in-out ${
          collapsed ? 'w-18' : 'w-60'
        } ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}
      >
        <div className="flex flex-col h-full overflow-y-auto">
          {/* Top: Brand & Workspace Switcher */}
          <div className="h-16 px-3.5 border-b border-slate-100 dark:border-slate-800/80 flex items-center justify-between shrink-0">
            {!collapsed ? (
              <div className="relative w-full">
                <button
                  type="button"
                  onClick={() => setWorkspaceMenuOpen(!workspaceMenuOpen)}
                  className="w-full flex items-center justify-between p-1.5 -ml-1 rounded-lg hover:bg-slate-100/70 dark:hover:bg-slate-800/60 transition-colors text-left group"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <VulnSealLogo size="sm" className="shrink-0" />
                    <div className="min-w-0">
                      <div className="text-xs font-semibold tracking-tight text-slate-900 dark:text-white truncate flex items-center gap-1.5">
                        <span>Vuln<span className="text-blue-600 dark:text-blue-400 font-bold">Seal</span></span>
                        <span className="px-1 py-0.2 rounded text-[9px] font-mono font-medium border border-blue-500/20 bg-blue-50 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400">
                          PRO
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-500 dark:text-slate-400 truncate flex items-center gap-1">
                        <span>Production Workspace</span>
                      </div>
                    </div>
                  </div>
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400 group-hover:text-slate-600 dark:group-hover:text-slate-300 shrink-0 ml-1 transition-colors" />
                </button>

                {/* Workspace Switcher Dropdown */}
                {workspaceMenuOpen && (
                  <div className="absolute top-12 left-0 right-0 z-50 p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-xl space-y-0.5 text-xs animate-in fade-in zoom-in-95">
                    <div className="px-2 py-1 text-[10px] font-mono text-slate-400">
                      SELECT WORKSPACE
                    </div>
                    <button
                      onClick={() => setWorkspaceMenuOpen(false)}
                      className="w-full flex items-center justify-between px-2 py-1.5 rounded text-left bg-blue-50 dark:bg-blue-950/50 text-blue-700 dark:text-blue-300 font-medium"
                    >
                      <div className="flex items-center gap-2">
                        <VulnSealLogo size="xs" />
                        <span>Default Workspace</span>
                      </div>
                      <span className="text-[10px] font-mono">Current</span>
                    </button>
                    <div className="pt-1 border-t border-slate-100 dark:border-slate-800 px-2 py-1 text-[11px] text-slate-500">
                      Multi-tenant isolated
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="w-full flex justify-center items-center py-2" title="VulnSeal">
                <VulnSealLogo size="sm" className="mx-auto" />
              </div>
            )}
          </div>

          {/* Navigation Links Grouped */}
          <nav className="p-3 space-y-4 flex-1">
            {/* Primary Section */}
            <div className="space-y-0.5">
              {primarySection.map((item) => renderNavButton(item))}
            </div>

            {/* Security Section */}
            <div className="space-y-0.5">
              {!collapsed && (
                <div className="px-3 pb-1 text-[10px] font-mono font-medium tracking-wider text-slate-400 dark:text-slate-500 uppercase">
                  Security
                </div>
              )}
              {securitySection.map((item) => renderNavButton(item))}
            </div>

            {/* Remediation Section */}
            <div className="space-y-0.5">
              {!collapsed && (
                <div className="px-3 pb-1 text-[10px] font-mono font-medium tracking-wider text-slate-400 dark:text-slate-500 uppercase">
                  Remediation
                </div>
              )}
              {remediationSection.map((item) => renderNavButton(item))}
            </div>

            {/* Activity Section */}
            <div className="space-y-0.5">
              {!collapsed && (
                <div className="px-3 pb-1 text-[10px] font-mono font-medium tracking-wider text-slate-400 dark:text-slate-500 uppercase">
                  Activity
                </div>
              )}
              {activitySection.map((item) => renderNavButton(item))}
            </div>

            {/* Demo Lab Section */}
            <div className="space-y-0.5 pt-2 border-t border-slate-100 dark:border-slate-800/60">
              {!collapsed && (
                <div className="px-3 pb-1 text-[10px] font-mono font-medium tracking-wider text-slate-400 dark:text-slate-500 uppercase">
                  Sandbox
                </div>
              )}
              {bottomSection.map((item) => renderNavButton(item))}
            </div>
          </nav>

          {/* Bottom collapse button & subtle status */}
          <div className="p-3 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between">
            {!collapsed && (
              <div className="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400 font-medium">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span>Network Guard Active</span>
              </div>
            )}
            <button
              onClick={onToggleCollapse}
              className={`p-1.5 rounded-md text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors ${
                collapsed ? 'mx-auto' : ''
              }`}
              title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            >
              {collapsed ? (
                <ChevronsRight className="w-4 h-4" />
              ) : (
                <ChevronsLeft className="w-4 h-4" />
              )}
            </button>
          </div>
        </div>
      </aside>
    </>
  );
};

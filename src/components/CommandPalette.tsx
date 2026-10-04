import React, { useEffect, useState, useRef } from 'react';
import { NavItem } from './Navigation';
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
  Search,
  ArrowRight,
  Sliders,
  X,
  Play,
  RotateCcw,
  CornerDownLeft,
} from 'lucide-react';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigate: (tab: NavItem) => void;
  onStartDemoScan: () => Promise<void>;
  onResetDemo: () => Promise<void>;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onNavigate,
  onStartDemoScan,
  onResetDemo,
}) => {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const commands = [
    {
      id: 'overview',
      title: 'Go to Overview Dashboard',
      category: 'Navigation',
      icon: LayoutDashboard,
      action: () => {
        onNavigate('overview');
        onClose();
      },
    },
    {
      id: 'targets',
      title: 'Manage Security Targets',
      category: 'Security',
      icon: Target,
      action: () => {
        onNavigate('targets');
        onClose();
      },
    },
    {
      id: 'scans',
      title: 'Run or Inspect Security Scans',
      category: 'Security',
      icon: Radar,
      action: () => {
        onNavigate('scans');
        onClose();
      },
    },
    {
      id: 'findings',
      title: 'View Open Vulnerabilities & Findings',
      category: 'Security',
      icon: ShieldAlert,
      action: () => {
        onNavigate('findings');
        onClose();
      },
    },
    {
      id: 'remediation',
      title: 'Patch Generation & Human Approval',
      category: 'Remediation',
      icon: Wrench,
      action: () => {
        onNavigate('remediation');
        onClose();
      },
    },
    {
      id: 'shadowfix',
      title: 'ShadowFix Isolated Verification',
      category: 'Remediation',
      icon: ShieldCheck,
      action: () => {
        onNavigate('shadowfix');
        onClose();
      },
    },
    {
      id: 'proofs',
      title: 'Cryptographic Proof of Fix Center',
      category: 'Compliance',
      icon: FileText,
      action: () => {
        onNavigate('proofs');
        onClose();
      },
    },
    {
      id: 'agents',
      title: 'Autonomous Agent Telemetry',
      category: 'Agents',
      icon: Activity,
      action: () => {
        onNavigate('agents');
        onClose();
      },
    },
    {
      id: 'audit',
      title: 'Tamper-Evident Audit Log',
      category: 'Compliance',
      icon: FileText,
      action: () => {
        onNavigate('audit');
        onClose();
      },
    },
    {
      id: 'settings',
      title: 'Database & System Settings',
      category: 'System',
      icon: Sliders,
      action: () => {
        onNavigate('settings');
        onClose();
      },
    },
    {
      id: 'demo',
      title: 'Demo Lab Target Portal',
      category: 'Demo Lab',
      icon: Terminal,
      action: () => {
        onNavigate('demo');
        onClose();
      },
    },
    {
      id: 'start-demo-scan',
      title: 'Launch Demo Security Scan Now',
      category: 'Quick Actions',
      icon: Play,
      action: async () => {
        onClose();
        await onStartDemoScan();
      },
    },
    {
      id: 'reset-demo',
      title: 'Reset Demo Target to Vulnerable State',
      category: 'Quick Actions',
      icon: RotateCcw,
      action: async () => {
        onClose();
        await onResetDemo();
      },
    },
  ];

  const filtered = commands.filter((cmd) =>
    cmd.title.toLowerCase().includes(query.toLowerCase()) ||
    cmd.category.toLowerCase().includes(query.toLowerCase())
  );

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        if (isOpen) {
          onClose();
        }
      } else if (e.key === 'Escape' && isOpen) {
        e.preventDefault();
        onClose();
      } else if (isOpen) {
        if (e.key === 'ArrowDown') {
          e.preventDefault();
          setSelectedIndex((prev) => (filtered.length > 0 ? (prev + 1) % filtered.length : 0));
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          setSelectedIndex((prev) => (filtered.length > 0 ? (prev - 1 + filtered.length) % filtered.length : 0));
        } else if (e.key === 'Enter') {
          e.preventDefault();
          if (filtered[selectedIndex]) {
            filtered[selectedIndex].action();
          }
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose, filtered, selectedIndex]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-16 sm:pt-24 p-4 bg-slate-950/40 backdrop-blur-xs transition-opacity animate-in fade-in duration-150"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input Bar */}
        <div className="flex items-center px-3.5 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <Search className="w-4 h-4 text-slate-400 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Type a command or jump to... (e.g. 'findings', 'scan', 'demo')"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full px-3 py-3 text-xs text-slate-900 dark:text-slate-100 bg-transparent placeholder-slate-400 focus:outline-hidden"
          />
          <button
            onClick={onClose}
            className="p-1 rounded-md text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            title="Close command palette (Escape)"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="max-h-72 overflow-y-auto p-1.5 space-y-0.5">
          {filtered.length > 0 ? (
            filtered.map((item, idx) => {
              const Icon = item.icon;
              const isSelected = idx === selectedIndex;
              return (
                <button
                  key={item.id}
                  onClick={item.action}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-left text-xs transition-colors ${
                    isSelected
                      ? 'bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 font-medium'
                      : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100/70 dark:hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <Icon
                      className={`w-4 h-4 shrink-0 transition-colors ${
                        isSelected ? 'text-blue-600 dark:text-blue-400' : 'text-slate-400'
                      }`}
                    />
                    <span className="truncate">{item.title}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] font-mono text-slate-400 bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded">
                      {item.category}
                    </span>
                    {isSelected && (
                      <CornerDownLeft className="w-3 h-3 text-blue-500 shrink-0" />
                    )}
                  </div>
                </button>
              );
            })
          ) : (
            <div className="p-6 text-center text-xs text-slate-400">
              No matching commands found for "{query}".
            </div>
          )}
        </div>

        {/* Footer shortcuts helper */}
        <div className="px-3.5 py-2 bg-slate-50 dark:bg-slate-950/60 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-[10.5px] text-slate-400 font-mono">
          <div className="flex items-center gap-3">
            <span>↑↓ to navigate</span>
            <span>↵ to select</span>
          </div>
          <button
            onClick={onClose}
            className="hover:text-slate-600 dark:hover:text-slate-200 transition-colors"
          >
            ESC to close
          </button>
        </div>
      </div>
    </div>
  );
};

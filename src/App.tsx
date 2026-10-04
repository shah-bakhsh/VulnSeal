import React, { useState, useEffect } from 'react';
import type {
  Target,
  ScanRun,
  Finding,
  ProofOfFix,
  AgentEvent,
  AuditLog,
} from './types/client';
import {
  fetchTargets,
  fetchScans,
  fetchFindings,
  fetchProofs,
  fetchAgentEvents,
  fetchAuditLogs,
  startScan,
  generateRemediation,
  approvePatch,
  rejectPatch,
  runShadowFix,
  resetDemo,
} from './lib/api';
import { Navigation, NavItem } from './components/Navigation';
import { Header } from './components/Header';
import { CommandPalette } from './components/CommandPalette';
import { OverviewView } from './components/OverviewView';
import { TargetsView } from './components/TargetsView';
import { ScansView } from './components/ScansView';
import { FindingsView } from './components/FindingsView';
import { RemediationView } from './components/RemediationView';
import { ShadowFixView } from './components/ShadowFixView';
import { ProofCenterView } from './components/ProofCenterView';
import { AgentActivityView } from './components/AgentActivityView';
import { AuditLogView } from './components/AuditLogView';
import { DemoPortalView } from './components/DemoPortalView';
import { SettingsView } from './components/SettingsView';
import { AuthModal } from './components/brand';

export function App() {
  const [currentTab, setCurrentTab] = useState<NavItem>('overview');
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    return (localStorage.getItem('vulnseal_theme') as 'light' | 'dark') || 'light';
  });
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() => {
    return localStorage.getItem('vulnseal_sidebar_collapsed') === 'true';
  });
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [authModalOpen, setAuthModalOpen] = useState(false);

  // Core Data State
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<ScanRun[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [proofs, setProofs] = useState<ProofOfFix[]>([]);
  const [agentEvents, setAgentEvents] = useState<AgentEvent[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);

  // Action Pending States
  const [isScanning, setIsScanning] = useState(false);
  const [isRemediating, setIsRemediating] = useState(false);
  const [isActionRunning, setIsActionRunning] = useState(false);
  const [notification, setNotification] = useState<{ message: string; type: 'success' | 'error' | 'info' } | null>(null);

  // Sync theme with HTML root element
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    localStorage.setItem('vulnseal_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  };

  const toggleSidebarCollapse = () => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      localStorage.setItem('vulnseal_sidebar_collapsed', String(next));
      return next;
    });
  };

  const showToast = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
    setNotification({ message, type });
    setTimeout(() => {
      setNotification((curr) => (curr?.message === message ? null : curr));
    }, 4000);
  };

  // Keyboard shortcut listener for Command Palette (⌘K / Ctrl+K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setCommandPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Load all system data with resilient fallback
  const loadData = async () => {
    try {
      const [tData, sData, fData, pData, eData, aData] = await Promise.all([
        fetchTargets().catch((err) => {
          console.warn('Targets fetch notice:', err.message);
          return null;
        }),
        fetchScans().catch((err) => {
          console.warn('Scans fetch notice:', err.message);
          return null;
        }),
        fetchFindings().catch((err) => {
          console.warn('Findings fetch notice:', err.message);
          return null;
        }),
        fetchProofs().catch((err) => {
          console.warn('Proofs fetch notice:', err.message);
          return null;
        }),
        fetchAgentEvents().catch((err) => {
          console.warn('Agent events fetch notice:', err.message);
          return null;
        }),
        fetchAuditLogs().catch((err) => {
          console.warn('Audit logs fetch notice:', err.message);
          return null;
        }),
      ]);

      if (tData) setTargets(tData);
      if (sData) setScans(sData);
      if (fData) setFindings(fData);
      if (pData) setProofs(pData);
      if (eData) setAgentEvents(eData);
      if (aData) setAuditLogs(aData);
    } catch (err: any) {
      console.warn('Background sync notice:', err.message);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 4000); // Polling for live status
    return () => clearInterval(interval);
  }, []);

  // Action Handlers
  const handleStartScan = async (targetId: string) => {
    setIsScanning(true);
    showToast('ScopeGuard validating target authorization and initiating scan...', 'info');
    try {
      await startScan(targetId);
      setCurrentTab('scans');
      await loadData();
      showToast('Scan launched successfully.', 'success');
    } catch (err: any) {
      showToast(err.message, 'error');
    } finally {
      setIsScanning(false);
    }
  };

  const handleStartDemoScan = async () => {
    const demoTarget = targets.find((t) => t.is_demo);
    if (!demoTarget) {
      showToast('Demo target not found.', 'error');
      return;
    }
    await handleStartScan(demoTarget.id);
  };

  const handleGenerateRemediation = async (findingId: string) => {
    setIsRemediating(true);
    showToast('RootCauseMapper & RemediationEngineer analyzing vulnerability...', 'info');
    try {
      await generateRemediation(findingId);
      await loadData();
      showToast('Patch candidate generated. Human approval required.', 'success');
    } catch (err: any) {
      showToast(err.message, 'error');
    } finally {
      setIsRemediating(false);
    }
  };

  const handleApprovePatch = async (patchId: string, patchHash: string, email: string) => {
    setIsActionRunning(true);
    try {
      await approvePatch(patchId, patchHash, email);
      await loadData();
      showToast('Cryptographic approval registered. Ready for ShadowFix.', 'success');
    } catch (err: any) {
      showToast(err.message, 'error');
    } finally {
      setIsActionRunning(false);
    }
  };

  const handleRejectPatch = async (patchId: string, reason: string, email: string) => {
    setIsActionRunning(true);
    try {
      await rejectPatch(patchId, reason, email);
      await loadData();
      showToast('Patch candidate rejected by operator.', 'info');
    } catch (err: any) {
      showToast(err.message, 'error');
    } finally {
      setIsActionRunning(false);
    }
  };

  const handleRunShadowFix = async (patchId: string) => {
    setIsActionRunning(true);
    showToast('ShadowFix digital twin running isolated build, replay, and regression tests...', 'info');
    try {
      const res = await runShadowFix(patchId);
      await loadData();
      if (res.verification_verdict === 'VERIFIED') {
        showToast('VERIFIED: Original vulnerability closed with 0 regressions. Proof of Fix issued!', 'success');
        setCurrentTab('proofs');
      } else {
        showToast(`Verification resulted in: ${res.verification_verdict}`, 'error');
      }
    } catch (err: any) {
      showToast(err.message, 'error');
    } finally {
      setIsActionRunning(false);
    }
  };

  const handleResetDemo = async () => {
    showToast('Restoring demo application to baseline...', 'info');
    try {
      await resetDemo();
      await loadData();
      showToast('Demo application restored to vulnerable baseline.', 'success');
    } catch (err: any) {
      showToast(err.message, 'error');
    }
  };

  const openFindingsCount = findings.filter(
    (f) => f.status !== 'verified' && f.status !== 'dismissed'
  ).length;

  return (
    <div className="min-h-screen flex bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-sans selection:bg-blue-600 selection:text-white">
      {/* Sidebar Navigation */}
      <Navigation
        currentTab={currentTab}
        onTabChange={setCurrentTab}
        openFindingsCount={openFindingsCount}
        verifiedFixesCount={proofs.length}
        mobileOpen={mobileNavOpen}
        onCloseMobile={() => setMobileNavOpen(false)}
        collapsed={sidebarCollapsed}
        onToggleCollapse={toggleSidebarCollapse}
      />

      {/* Main Viewport Container */}
      <div className="flex-1 flex flex-col min-w-0">
        <Header
          currentTab={currentTab}
          theme={theme}
          onToggleTheme={toggleTheme}
          onOpenMobileNav={() => setMobileNavOpen(true)}
          onOpenCommandPalette={() => setCommandPaletteOpen(true)}
          onOpenAuth={() => setAuthModalOpen(true)}
        />

        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto">
          {currentTab === 'overview' && (
            <OverviewView
              targets={targets}
              scans={scans}
              findings={findings}
              proofs={proofs}
              agentEvents={agentEvents}
              onNavigate={setCurrentTab}
              onStartDemoScan={handleStartDemoScan}
              isScanning={isScanning}
            />
          )}

          {currentTab === 'targets' && (
            <TargetsView
              targets={targets}
              onRefresh={loadData}
              onStartScan={handleStartScan}
              isScanning={isScanning}
            />
          )}

          {currentTab === 'scans' && (
            <ScansView
              scans={scans}
              targets={targets}
              agentEvents={agentEvents}
              onStartScan={handleStartScan}
              onRefresh={loadData}
              isScanning={isScanning}
            />
          )}

          {currentTab === 'findings' && (
            <FindingsView
              findings={findings}
              onGenerateRemediation={handleGenerateRemediation}
              onNavigate={setCurrentTab}
              isRemediating={isRemediating}
            />
          )}

          {currentTab === 'remediation' && (
            <RemediationView
              findings={findings}
              onApprovePatch={handleApprovePatch}
              onRejectPatch={handleRejectPatch}
              onRunShadowFix={handleRunShadowFix}
              onNavigate={setCurrentTab}
              isActionRunning={isActionRunning}
            />
          )}

          {currentTab === 'shadowfix' && (
            <ShadowFixView
              findings={findings}
              onNavigate={setCurrentTab}
              onRunShadowFix={handleRunShadowFix}
              isActionRunning={isActionRunning}
            />
          )}

          {currentTab === 'proofs' && (
            <ProofCenterView proofs={proofs} />
          )}

          {currentTab === 'agents' && (
            <AgentActivityView events={agentEvents} />
          )}

          {currentTab === 'audit' && (
            <AuditLogView logs={auditLogs} />
          )}

          {currentTab === 'demo' && (
            <DemoPortalView
              onStartDemoScan={handleStartDemoScan}
              onResetDemo={handleResetDemo}
              onNavigate={setCurrentTab}
              isScanning={isScanning}
            />
          )}

          {currentTab === 'settings' && (
            <SettingsView />
          )}
        </main>
      </div>

      {/* Global Command Palette (⌘K) */}
      <CommandPalette
        isOpen={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
        onNavigate={setCurrentTab}
        onStartDemoScan={handleStartDemoScan}
        onResetDemo={handleResetDemo}
      />

      {/* Operator Authentication & Identity Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
      />

      {/* Global Toast Notification */}
      {notification && (
        <div
          className={`fixed bottom-5 right-5 z-50 px-4 py-3 rounded-lg shadow-xl text-xs font-semibold flex items-center gap-2 border transition-all ${
            notification.type === 'success'
              ? 'bg-emerald-950/90 text-emerald-200 border-emerald-800'
              : notification.type === 'error'
              ? 'bg-red-950/90 text-red-200 border-red-800'
              : 'bg-slate-900/90 text-slate-100 border-slate-700'
          }`}
        >
          <span>{notification.message}</span>
        </div>
      )}
    </div>
  );
}

export default App;

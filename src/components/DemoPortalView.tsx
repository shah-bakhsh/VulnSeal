import React, { useState } from 'react';
import {
  Terminal,
  Send,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  RotateCcw,
  Play,
  Lock,
  ChevronDown,
  ChevronRight,
  Globe,
  Shield,
  Layers,
} from 'lucide-react';
import { NavItem } from './Navigation';

interface DemoPortalViewProps {
  onStartDemoScan: () => Promise<void>;
  onResetDemo: () => Promise<void>;
  onNavigate: (tab: NavItem) => void;
  isScanning: boolean;
}

export const DemoPortalView: React.FC<DemoPortalViewProps> = ({
  onStartDemoScan,
  onResetDemo,
  onNavigate,
  isScanning,
}) => {
  const [responseHeaders, setResponseHeaders] = useState<Record<string, string> | null>(null);
  const [responseBody, setResponseBody] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [showConfirmReset, setShowConfirmReset] = useState<boolean>(false);
  const [resetting, setResetting] = useState<boolean>(false);
  const [showDeveloperFixtures, setShowDeveloperFixtures] = useState<boolean>(false);

  const handleTestLogin = async () => {
    setLoading(true);
    try {
      const res = await fetch('/demo-target/login', { method: 'POST' });
      const data = await res.json();
      const headersObj: Record<string, string> = {};
      res.headers.forEach((val, key) => {
        headersObj[key] = val;
      });
      setResponseHeaders(headersObj);
      setResponseBody(data);
    } catch (err: any) {
      setResponseBody({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const handleConfirmReset = async () => {
    setResetting(true);
    try {
      await onResetDemo();
      setShowConfirmReset(false);
      setResponseHeaders(null);
      setResponseBody(null);
    } finally {
      setResetting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-100 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
              Demo Lab
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-100 dark:bg-amber-950/60 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-900">
              SAFE SANDBOX
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            An intentionally vulnerable application owned by VulnSeal for safe, authorized demonstration of the remediation loop.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowConfirmReset(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors shadow-2xs"
          >
            <RotateCcw className="w-3.5 h-3.5 text-slate-500" />
            <span>Reset Demo State</span>
          </button>

          <button
            onClick={onStartDemoScan}
            disabled={isScanning}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition-colors disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{isScanning ? 'Scan Running...' : 'Launch Demo Scan'}</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Demo Environment Overview Card */}
        <div className="rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4 shadow-2xs">
          <div className="flex items-center gap-2 pb-2 border-b border-slate-100 dark:border-slate-800">
            <Terminal className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <h2 className="text-xs font-bold text-slate-900 dark:text-white">
              Demo Environment Configuration
            </h2>
          </div>

          <div className="space-y-3 text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
            <p>
              This sandbox provides an authentic target for end-to-end testing. When you launch a demo scan, VulnSeal will run deterministic security checks against its login endpoint, confirm weaknesses, generate a code fix, and verify it in ShadowFix.
            </p>

            <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800 space-y-1.5 font-mono text-[11px]">
              <div>Target: <strong>Demo Banking Application</strong></div>
              <div>Endpoint: <strong>http://localhost:3000/demo-target</strong></div>
              <div>Authorization: <strong className="text-emerald-600 dark:text-emerald-400">Pre-authorized (Allowlisted)</strong></div>
              <div>Scope: <strong>Strict Localhost Sandbox Only</strong></div>
            </div>

            {/* Collapsible Developer Test Fixtures */}
            <div className="pt-2 border-t border-slate-100 dark:border-slate-800">
              <button
                type="button"
                onClick={() => setShowDeveloperFixtures(!showDeveloperFixtures)}
                className="flex items-center justify-between w-full text-[11px] font-semibold text-slate-700 dark:text-slate-300 hover:text-blue-600 py-1"
              >
                <span>Developer Controls: Reveal Expected Test Fixtures</span>
                {showDeveloperFixtures ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              </button>

              {showDeveloperFixtures && (
                <div className="mt-2 space-y-2 text-[11px] font-mono text-slate-500 bg-slate-50 dark:bg-slate-950 p-3 rounded-lg border border-slate-200 dark:border-slate-800 animate-in fade-in">
                  <div>• Rule SEC_COOKIE_INSECURE: session token missing Secure directive</div>
                  <div>• Rule CORS_WILDCARD_CREDENTIALS: Access-Control-Allow-Origin wildcard</div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Live HTTP Interaction Tester */}
        <div className="rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4 shadow-2xs">
          <div className="flex items-center justify-between pb-2 border-b border-slate-100 dark:border-slate-800">
            <h2 className="text-xs font-bold text-slate-900 dark:text-white">
              Live HTTP Request Tester
            </h2>
            <span className="text-[11px] font-mono text-slate-400">POST /demo-target/login</span>
          </div>

          <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
            Send a live test request to the demo login endpoint to inspect returned session headers in real-time.
          </p>

          <button
            onClick={handleTestLogin}
            disabled={loading}
            className="w-full py-2 px-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 hover:bg-slate-100 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-900 dark:text-slate-100 font-medium text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
          >
            <Send className="w-3.5 h-3.5" />
            <span>{loading ? 'Sending Request...' : 'Send Test Request & Inspect Headers'}</span>
          </button>

          {responseBody && (
            <div className="space-y-2 text-xs animate-in fade-in">
              <span className="font-semibold text-slate-800 dark:text-slate-200 block text-[11px]">
                Server Response:
              </span>
              <pre className="p-3 rounded-lg bg-slate-950 font-mono text-[11px] text-slate-200 overflow-x-auto max-h-48 border border-slate-800">
                {JSON.stringify(responseBody, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>

      {/* Reset Confirmation Modal */}
      {showConfirmReset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-2xl space-y-4 animate-in fade-in zoom-in-95">
            <div className="flex items-center gap-2 text-amber-600 dark:text-amber-400">
              <AlertTriangle className="w-5 h-5" />
              <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                Reset Demo State?
              </h3>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
              This will restore the demo application configuration to its baseline vulnerable state and clear demo scans, findings, and proofs.
            </p>

            <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex justify-end gap-2 text-xs">
              <button
                onClick={() => setShowConfirmReset(false)}
                className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 font-medium hover:bg-slate-50 dark:hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmReset}
                disabled={resetting}
                className="px-4 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-semibold shadow-xs disabled:opacity-50"
              >
                {resetting ? 'Resetting...' : 'Confirm Reset'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

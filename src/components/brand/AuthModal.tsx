import React, { useState } from 'react';
import { VulnSealLogo } from './VulnSealLogo';
import { X, Lock, Key, ArrowRight, ShieldCheck, CheckCircle2, User } from 'lucide-react';

export interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentUser?: string;
  onLogin?: (email: string) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  currentUser = 'engineer@vulnseal.security',
  onLogin,
}) => {
  const [email, setEmail] = useState(currentUser);
  const [authMethod, setAuthMethod] = useState<'sso' | 'apiKey' | 'session'>('session');
  const [submitted, setSubmitted] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitted(true);
    if (onLogin) {
      onLogin(email);
    }
    setTimeout(() => {
      setSubmitted(false);
      onClose();
    }, 600);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-xs animate-in fade-in duration-200">
      <div className="w-full max-w-md rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-8 shadow-2xl space-y-6 relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors"
          aria-label="Close authentication modal"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Brand Lockup: Logo -> VulnSeal -> Tagline */}
        <div className="text-center space-y-3 pt-1">
          <div className="flex justify-center">
            <VulnSealLogo size="xl" className="drop-shadow-sm" />
          </div>

          <div>
            <h2 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
              Vuln<span className="text-blue-600 dark:text-blue-400">Seal</span>
            </h2>
            <div className="text-sm font-semibold text-blue-600 dark:text-blue-400 mt-0.5">
              Find. Fix. Prove.
            </div>
          </div>

          <p className="text-xs text-slate-500 dark:text-slate-400 max-w-xs mx-auto leading-relaxed">
            Autonomous security remediation with verified proof.
          </p>
        </div>

        {/* Auth Mode Tabs */}
        <div className="p-1 rounded-xl bg-slate-100 dark:bg-slate-800/70 border border-slate-200 dark:border-slate-800 grid grid-cols-2 text-xs font-semibold">
          <button
            type="button"
            onClick={() => setAuthMethod('session')}
            className={`py-1.5 rounded-lg transition-all ${
              authMethod === 'session'
                ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs'
                : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            Operator Session
          </button>
          <button
            type="button"
            onClick={() => setAuthMethod('sso')}
            className={`py-1.5 rounded-lg transition-all ${
              authMethod === 'sso'
                ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs'
                : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            Enterprise SSO
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div className="space-y-1.5">
            <label className="block font-semibold text-slate-700 dark:text-slate-300">
              Authorized Operator Email
            </label>
            <div className="relative">
              <User className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full pl-9 pr-3 py-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-xs"
                placeholder="name@company.com"
              />
            </div>
          </div>

          <div className="p-3 rounded-lg border border-blue-100 dark:border-blue-900/40 bg-blue-50/50 dark:bg-blue-950/20 text-slate-600 dark:text-slate-300 flex items-start gap-2.5">
            <ShieldCheck className="w-4 h-4 text-blue-600 dark:text-blue-400 shrink-0 mt-0.5" />
            <div className="text-[11px] leading-relaxed">
              Active ScopeGuard authorization role: <strong>Security Engineer (Remediation Master)</strong>.
            </div>
          </div>

          <button
            type="submit"
            disabled={submitted}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-semibold shadow-xs transition-colors cursor-pointer"
          >
            {submitted ? (
              <>
                <CheckCircle2 className="w-4 h-4 text-white animate-bounce" />
                <span>Session Verified</span>
              </>
            ) : (
              <>
                <span>Continue to Remediation Console</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        <div className="pt-2 border-t border-slate-100 dark:border-slate-800 text-center">
          <div className="inline-flex items-center gap-1.5 text-[11px] text-slate-400 font-mono">
            <Lock className="w-3 h-3 text-emerald-500" />
            <span>End-to-End Cryptographically Verified Loop</span>
          </div>
        </div>
      </div>
    </div>
  );
};

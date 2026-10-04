import {
  Workspace,
  Target,
  AuthorizationChallenge,
  ScanRun,
  Finding,
  FindingEvidence,
  RootCause,
  PatchCandidate,
  RemediationApproval,
  ShadowFixRun,
  VerificationResult,
  ProofOfFix,
  AgentEvent,
  AuditLog,
} from './types';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  syncTargetToSupabase,
  deleteTargetFromSupabase,
  syncScanToSupabase,
  syncFindingToSupabase,
  syncProofToSupabase,
  syncAuditLogToSupabase,
  supabase,
} from './supabase';

class VulnSealDatabase {
  private workspaces: Map<string, Workspace> = new Map();
  private targets: Map<string, Target> = new Map();
  private challenges: Map<string, AuthorizationChallenge> = new Map();
  private scans: Map<string, ScanRun> = new Map();
  private findings: Map<string, Finding> = new Map();
  private evidence: Map<string, FindingEvidence> = new Map();
  private rootCauses: Map<string, RootCause> = new Map();
  private patches: Map<string, PatchCandidate> = new Map();
  private approvals: Map<string, RemediationApproval> = new Map();
  private shadowFixRuns: Map<string, ShadowFixRun> = new Map();
  private verifications: Map<string, VerificationResult> = new Map();
  private proofs: Map<string, ProofOfFix> = new Map();
  private agentEvents: AgentEvent[] = [];
  private auditLogs: AuditLog[] = [];

  private dbFilePath: string = path.join(process.cwd(), '.vulnseal-db.json');

  constructor() {
    const loaded = this.loadFromDisk();
    if (!loaded) {
      this.seedInitialData();
      this.saveToDisk();
    }
    this.loadFromSupabase();
  }

  private async loadFromSupabase() {
    if (!supabase) return;
    try {
      const { data: supaTargets, error } = await supabase.from('targets').select('*');
      if (!error && supaTargets && supaTargets.length > 0) {
        for (const t of supaTargets) {
          this.targets.set(t.id, t);
        }
      }
    } catch (err) {
      console.warn('[Supabase] Initial load notice:', err);
    }
  }

  private saveToDisk() {
    try {
      const data = {
        workspaces: Array.from(this.workspaces.entries()),
        targets: Array.from(this.targets.entries()),
        challenges: Array.from(this.challenges.entries()),
        scans: Array.from(this.scans.entries()),
        findings: Array.from(this.findings.entries()),
        evidence: Array.from(this.evidence.entries()),
        rootCauses: Array.from(this.rootCauses.entries()),
        patches: Array.from(this.patches.entries()),
        approvals: Array.from(this.approvals.entries()),
        shadowFixRuns: Array.from(this.shadowFixRuns.entries()),
        verifications: Array.from(this.verifications.entries()),
        proofs: Array.from(this.proofs.entries()),
        agentEvents: this.agentEvents,
        auditLogs: this.auditLogs,
      };
      fs.writeFileSync(this.dbFilePath, JSON.stringify(data, null, 2), 'utf8');
    } catch (err) {
      // Non-fatal if filesystem is read-only
      console.warn('VulnSeal persistent storage write notice:', err);
    }
  }

  private loadFromDisk(): boolean {
    try {
      if (!fs.existsSync(this.dbFilePath)) return false;
      const raw = fs.readFileSync(this.dbFilePath, 'utf8');
      const data = JSON.parse(raw);
      if (!data.targets || !data.workspaces) return false;

      this.workspaces = new Map(data.workspaces);
      this.targets = new Map(data.targets);
      this.challenges = new Map(data.challenges || []);
      this.scans = new Map(data.scans || []);
      this.findings = new Map(data.findings || []);
      this.evidence = new Map(data.evidence || []);
      this.rootCauses = new Map(data.rootCauses || []);
      this.patches = new Map(data.patches || []);
      this.approvals = new Map(data.approvals || []);
      this.shadowFixRuns = new Map(data.shadowFixRuns || []);
      this.verifications = new Map(data.verifications || []);
      this.proofs = new Map(data.proofs || []);
      this.agentEvents = data.agentEvents || [];
      this.auditLogs = data.auditLogs || [];
      return true;
    } catch (err) {
      return false;
    }
  }

  public seedInitialData() {
    // 1. Default Workspace
    const defaultWorkspace: Workspace = {
      id: 'ws_default_01',
      name: 'Default Workspace',
      slug: 'default-workspace',
      created_at: new Date(Date.now() - 86400000).toISOString(),
    };
    this.workspaces.set(defaultWorkspace.id, defaultWorkspace);

    // 2. VulnSeal Owned Intentionally Vulnerable Demo Target
    const demoTargetId = 'target_demo_01';
    const demoTarget: Target = {
      id: demoTargetId,
      workspace_id: defaultWorkspace.id,
      url: 'http://localhost:3000/demo-target',
      name: 'VulnSeal Intentionally Vulnerable Demo Target',
      is_demo: true,
      status: 'authorized', // Demo target is pre-authorized
      authorized_at: new Date().toISOString(),
      security_score: null, // Not assessed until first scan is run
      open_findings_count: 0,
      verified_fixes_count: 0,
      created_at: new Date().toISOString(),
    };
    this.targets.set(demoTarget.id, demoTarget);

    // 3. Demo Challenge Token
    const challenge: AuthorizationChallenge = {
      id: 'auth_chal_demo_01',
      target_id: demoTarget.id,
      method: 'demo_allowlist',
      token: 'vulnseal-demo-authorized-target-token',
      expected_value: 'vulnseal-verification=vs_token_demo_valid_99a8',
      status: 'verified',
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 86400000 * 30).toISOString(),
      verified_at: new Date().toISOString(),
    };
    this.challenges.set(challenge.id, challenge);

    this.createAuditLog({
      workspace_id: defaultWorkspace.id,
      action: 'SYSTEM_INITIALIZED',
      actor: 'SystemEngine',
      resource_type: 'workspace',
      resource_id: defaultWorkspace.id,
      decision: 'ALLOWED',
      details: { message: 'VulnSeal enterprise database initialized with isolated demo target.' },
    });
  }

  // Workspaces
  public getWorkspaces(): Workspace[] {
    return Array.from(this.workspaces.values());
  }

  public getWorkspace(id: string): Workspace | undefined {
    return this.workspaces.get(id);
  }

  // Targets
  public getTargets(workspaceId: string): Target[] {
    return Array.from(this.targets.values()).filter((t) => t.workspace_id === workspaceId);
  }

  public getTarget(id: string): Target | undefined {
    return this.targets.get(id);
  }

  public createTarget(target: Omit<Target, 'id' | 'created_at' | 'open_findings_count' | 'verified_fixes_count' | 'security_score'>): Target {
    const id = `target_${crypto.randomUUID().slice(0, 8)}`;
    const newTarget: Target = {
      ...target,
      id,
      security_score: null, // Null until first completed scan
      open_findings_count: 0,
      verified_fixes_count: 0,
      created_at: new Date().toISOString(),
    };
    this.targets.set(id, newTarget);
    this.saveToDisk();
    syncTargetToSupabase(newTarget);
    return newTarget;
  }

  public updateTarget(id: string, updates: Partial<Target>): Target | undefined {
    const target = this.targets.get(id);
    if (!target) return undefined;
    const updated = { ...target, ...updates };
    this.targets.set(id, updated);
    this.saveToDisk();
    syncTargetToSupabase(updated);
    return updated;
  }

  public deleteTarget(id: string): boolean {
    const target = this.targets.get(id);
    if (!target) return false;

    this.targets.delete(id);
    deleteTargetFromSupabase(id);

    // Clean up associated challenges, findings, and scans
    for (const [cId, c] of this.challenges.entries()) {
      if (c.target_id === id) this.challenges.delete(cId);
    }
    for (const [fId, f] of this.findings.entries()) {
      if (f.target_id === id) {
        this.findings.delete(fId);
        if (f.evidence) this.evidence.delete(f.evidence.id);
      }
    }
    for (const [sId, s] of this.scans.entries()) {
      if (s.target_id === id) this.scans.delete(sId);
    }

    this.createAuditLog({
      workspace_id: target.workspace_id,
      action: 'TARGET_DELETED',
      actor: 'SecurityEngineer',
      resource_type: 'target',
      resource_id: id,
      decision: 'ALLOWED',
      details: { name: target.name, url: target.url },
    });

    this.saveToDisk();
    return true;
  }

  // Challenges
  public createChallenge(targetId: string, method: 'meta_tag' | 'dns_txt' | 'demo_allowlist'): AuthorizationChallenge {
    const token = `vs_token_${crypto.randomBytes(8).toString('hex')}`;
    const challenge: AuthorizationChallenge = {
      id: `chal_${crypto.randomUUID().slice(0, 8)}`,
      target_id: targetId,
      method,
      token,
      expected_value: `vulnseal-verification=${token}`,
      status: 'pending',
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 86400000 * 30).toISOString(),
    };
    this.challenges.set(challenge.id, challenge);
    this.saveToDisk();
    return challenge;
  }

  public getChallenge(id: string): AuthorizationChallenge | undefined {
    return this.challenges.get(id);
  }

  public getChallengeForTarget(targetId: string): AuthorizationChallenge | undefined {
    return Array.from(this.challenges.values()).find((c) => c.target_id === targetId);
  }

  public updateChallenge(id: string, updates: Partial<AuthorizationChallenge>): AuthorizationChallenge | undefined {
    const chal = this.challenges.get(id);
    if (!chal) return undefined;
    const updated = { ...chal, ...updates };
    this.challenges.set(id, updated);
    this.saveToDisk();
    return updated;
  }

  // Scans
  public getScans(workspaceId: string): ScanRun[] {
    return Array.from(this.scans.values())
      .filter((s) => s.workspace_id === workspaceId)
      .sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime());
  }

  public getScan(id: string): ScanRun | undefined {
    return this.scans.get(id);
  }

  public createScan(scan: Omit<ScanRun, 'id'>): ScanRun {
    const id = `scan_${crypto.randomUUID().slice(0, 8)}`;
    const newScan: ScanRun = { ...scan, id };
    this.scans.set(id, newScan);
    this.saveToDisk();
    syncScanToSupabase(newScan);
    return newScan;
  }

  public updateScan(id: string, updates: Partial<ScanRun>): ScanRun | undefined {
    const s = this.scans.get(id);
    if (!s) return undefined;
    const updated = { ...s, ...updates };
    this.scans.set(id, updated);
    this.saveToDisk();
    syncScanToSupabase(updated);
    return updated;
  }

  // Findings & Evidence
  public getFindings(workspaceId: string): Finding[] {
    return Array.from(this.findings.values())
      .filter((f) => f.workspace_id === workspaceId)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  public getFinding(id: string): Finding | undefined {
    return this.findings.get(id);
  }

  public createFinding(finding: Omit<Finding, 'id' | 'created_at' | 'updated_at'>): Finding {
    const id = `fnd_${crypto.randomUUID().slice(0, 8)}`;
    const now = new Date().toISOString();
    const newFinding: Finding = {
      ...finding,
      id,
      created_at: now,
      updated_at: now,
    };
    this.findings.set(id, newFinding);

    // Save evidence
    if (finding.evidence) {
      finding.evidence.finding_id = id;
      this.evidence.set(finding.evidence.id, finding.evidence);
    }

    this.recalculateTargetScore(finding.target_id);
    this.saveToDisk();
    syncFindingToSupabase(newFinding);
    return newFinding;
  }

  public updateFinding(id: string, updates: Partial<Finding>): Finding | undefined {
    const f = this.findings.get(id);
    if (!f) return undefined;
    const updated = { ...f, ...updates, updated_at: new Date().toISOString() };
    this.findings.set(id, updated);
    this.recalculateTargetScore(f.target_id);
    this.saveToDisk();
    syncFindingToSupabase(updated);
    return updated;
  }

  // Root Causes & Patches
  public setRootCause(rootCause: RootCause) {
    this.rootCauses.set(rootCause.finding_id, rootCause);
    this.saveToDisk();
  }

  public getRootCause(findingId: string): RootCause | undefined {
    return this.rootCauses.get(findingId);
  }

  public createPatch(patch: Omit<PatchCandidate, 'id' | 'created_at'> & { id?: string }): PatchCandidate {
    const id = patch.id || `ptch_${crypto.randomUUID().slice(0, 8)}`;
    const newPatch: PatchCandidate = {
      ...patch,
      id,
      created_at: new Date().toISOString(),
    };
    this.patches.set(id, newPatch);
    this.saveToDisk();
    return newPatch;
  }

  public getPatch(id: string): PatchCandidate | undefined {
    return this.patches.get(id);
  }

  public getPatchForFinding(findingId: string): PatchCandidate | undefined {
    return Array.from(this.patches.values()).find((p) => p.finding_id === findingId);
  }

  // Approvals
  public createApproval(approval: Omit<RemediationApproval, 'id' | 'approved_at'>): RemediationApproval {
    const id = `appr_${crypto.randomUUID().slice(0, 8)}`;
    const newApproval: RemediationApproval = {
      ...approval,
      id,
      approved_at: new Date().toISOString(),
    };
    this.approvals.set(id, newApproval);
    this.saveToDisk();
    return newApproval;
  }

  public getApprovalForPatch(patchId: string): RemediationApproval | undefined {
    return Array.from(this.approvals.values()).find((a) => a.patch_id === patchId);
  }

  // ShadowFix Runs & Verifications
  public createShadowFixRun(run: Omit<ShadowFixRun, 'id'>): ShadowFixRun {
    const id = `sfx_${crypto.randomUUID().slice(0, 8)}`;
    const newRun: ShadowFixRun = { ...run, id };
    this.shadowFixRuns.set(id, newRun);
    this.saveToDisk();
    return newRun;
  }

  public getShadowFixRun(id: string): ShadowFixRun | undefined {
    return this.shadowFixRuns.get(id);
  }

  public updateShadowFixRun(id: string, updates: Partial<ShadowFixRun>): ShadowFixRun | undefined {
    const run = this.shadowFixRuns.get(id);
    if (!run) return undefined;
    const updated = { ...run, ...updates };
    this.shadowFixRuns.set(id, updated);
    this.saveToDisk();
    return updated;
  }

  public createVerification(verif: Omit<VerificationResult, 'id' | 'verified_at'> & { verified_at?: string }): VerificationResult {
    const id = `verif_${crypto.randomUUID().slice(0, 8)}`;
    const newVerif: VerificationResult = {
      ...verif,
      id,
      verified_at: verif.verified_at || new Date().toISOString(),
    };
    this.verifications.set(id, newVerif);
    this.saveToDisk();
    return newVerif;
  }

  public getVerification(id: string): VerificationResult | undefined {
    return this.verifications.get(id);
  }

  // Proofs of Fix
  public getProofs(workspaceId: string): ProofOfFix[] {
    return Array.from(this.proofs.values())
      .filter((p) => p.workspace_id === workspaceId)
      .sort((a, b) => new Date(b.verified_at).getTime() - new Date(a.verified_at).getTime());
  }

  public getProof(id: string): ProofOfFix | undefined {
    return this.proofs.get(id);
  }

  public createProof(proof: Omit<ProofOfFix, 'id' | 'verified_at' | 'proof_hash'>): ProofOfFix {
    const id = `proof_${crypto.randomUUID().slice(0, 8)}`;
    const verified_at = new Date().toISOString();
    const proofMaterial = `${id}|${proof.finding_id}|${proof.patch_hash}|${proof.verifier_verdict}|${verified_at}`;
    const proof_hash = crypto.createHash('sha256').update(proofMaterial).digest('hex');

    const newProof: ProofOfFix = {
      ...proof,
      id,
      verified_at,
      proof_hash,
    };
    this.proofs.set(id, newProof);

    const finding = this.findings.get(proof.finding_id);
    if (finding) {
      this.recalculateTargetScore(finding.target_id);
    }

    this.saveToDisk();
    syncProofToSupabase(newProof);
    return newProof;
  }

  // Agent Events
  public recordAgentEvent(event: Omit<AgentEvent, 'id' | 'created_at'>): AgentEvent {
    const id = `evt_${crypto.randomUUID().slice(0, 8)}`;
    const newEvent: AgentEvent = {
      ...event,
      id,
      created_at: new Date().toISOString(),
    };
    this.agentEvents.push(newEvent);
    // Keep max 200 events in memory
    if (this.agentEvents.length > 200) {
      this.agentEvents.shift();
    }
    this.saveToDisk();
    return newEvent;
  }

  public getAgentEvents(workspaceId: string, limit: number = 50): AgentEvent[] {
    return this.agentEvents
      .filter((e) => e.workspace_id === workspaceId)
      .slice(-limit)
      .reverse();
  }

  // Audit Logs
  public createAuditLog(log: Omit<AuditLog, 'id' | 'timestamp'>): AuditLog {
    const id = `aud_${crypto.randomUUID().slice(0, 8)}`;
    const newLog: AuditLog = {
      ...log,
      id,
      timestamp: new Date().toISOString(),
    };
    this.auditLogs.push(newLog);
    // Keep max 200 audit logs
    if (this.auditLogs.length > 200) {
      this.auditLogs.shift();
    }
    this.saveToDisk();
    syncAuditLogToSupabase(newLog);
    return newLog;
  }

  public getAuditLogs(workspaceId: string, limit: number = 100): AuditLog[] {
    return this.auditLogs
      .filter((l) => l.workspace_id === workspaceId)
      .slice(-limit)
      .reverse();
  }

  // Deterministic VulnSeal Security Score Calculation
  // If no completed scan exists for target: security_score is null (not assessed).
  // Baseline on successful scan: 100.
  // Critical: -25, High: -15, Medium: -7, Low: -3.
  // Verified fixes restore the points.
  public recalculateTargetScore(targetId: string) {
    const target = this.targets.get(targetId);
    if (!target) return;

    const targetScans = Array.from(this.scans.values()).filter(
      (s) => s.target_id === targetId && (s.status === 'completed' || s.status === 'completed_with_warnings')
    );

    const targetFindings = Array.from(this.findings.values()).filter(
      (f) => f.target_id === targetId
    );

    let openCount = 0;
    let verifiedCount = 0;
    let score = 100;

    for (const f of targetFindings) {
      if (f.status === 'verified') {
        verifiedCount++;
        continue;
      }
      if (f.status === 'dismissed') continue;

      openCount++;
      if (f.severity === 'critical') score -= 25;
      else if (f.severity === 'high') score -= 15;
      else if (f.severity === 'medium') score -= 7;
      else if (f.severity === 'low') score -= 3;
    }

    if (targetScans.length === 0) {
      target.security_score = null;
    } else {
      target.security_score = Math.max(0, Math.min(100, score));
    }

    target.open_findings_count = openCount;
    target.verified_fixes_count = verifiedCount;
    this.saveToDisk();
    syncTargetToSupabase(target);
  }

  // Safe Demo Reset
  public resetDemoState(workspaceId: string = 'ws_default_01') {
    // Remove all findings, scans, patches, proofs associated with the demo target
    const demoTarget = Array.from(this.targets.values()).find((t) => t.is_demo);
    if (!demoTarget) return;

    for (const [id, f] of this.findings.entries()) {
      if (f.target_id === demoTarget.id) {
        this.findings.delete(id);
      }
    }

    for (const [id, s] of this.scans.entries()) {
      if (s.target_id === demoTarget.id) {
        this.scans.delete(id);
      }
    }

    for (const [id, p] of this.proofs.entries()) {
      if (p.target_url.includes('demo-target')) {
        this.proofs.delete(id);
      }
    }

    demoTarget.security_score = null;
    demoTarget.open_findings_count = 0;
    demoTarget.verified_fixes_count = 0;
    demoTarget.last_scan_at = undefined;
    demoTarget.status = 'authorized';

    this.createAuditLog({
      workspace_id: workspaceId,
      action: 'DEMO_STATE_RESET',
      actor: 'SecurityEngineer',
      resource_type: 'target',
      resource_id: demoTarget.id,
      decision: 'ALLOWED',
      details: { message: 'Demo environment restored to fresh vulnerable baseline.' },
    });

    this.saveToDisk();
  }
}

export const db = new VulnSealDatabase();

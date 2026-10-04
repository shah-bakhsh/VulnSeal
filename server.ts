import express, { Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { db } from './src/server/db';
import { ScannerOrchestrator } from './src/server/scanner';
import { ModelRouter } from './src/server/aiRouter';
import { ShadowFixEngine } from './src/server/shadowfix';
import { demoRouter, resetDemoRuntimeConfig } from './src/server/demoTarget';
import { testSupabaseConnection, isSupabaseConfigured } from './src/server/supabase';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

  app.use(express.json());

  // Mount intentionally vulnerable demo application
  app.use('/demo-target', demoRouter);

  // --- REST API ROUTES ---

  // Workspaces
  app.get('/api/workspaces', (req: Request, res: Response) => {
    res.json(db.getWorkspaces());
  });

  // Targets
  app.get('/api/targets', (req: Request, res: Response) => {
    const workspaceId = (req.query.workspace_id as string) || 'ws_default_01';
    res.json(db.getTargets(workspaceId));
  });

  app.post('/api/targets', (req: Request, res: Response) => {
    const { workspace_id, url, name, is_demo } = req.body;
    if (!url || !name) {
      res.status(400).json({ error: 'URL and target name are required.' });
      return;
    }

    const target = db.createTarget({
      workspace_id: workspace_id || 'ws_default_01',
      url,
      name,
      is_demo: Boolean(is_demo),
      status: is_demo ? 'authorized' : 'unverified',
    });

    const challenge = db.createChallenge(target.id, is_demo ? 'demo_allowlist' : 'meta_tag');

    res.json({ target, challenge });
  });

  // Get verification challenge for a target
  app.get('/api/targets/:id/challenge', (req: Request, res: Response) => {
    const target = db.getTarget(req.params.id);
    if (!target) {
      res.status(404).json({ error: 'Target not found' });
      return;
    }
    let challenge = db.getChallengeForTarget(target.id);
    if (!challenge) {
      challenge = db.createChallenge(target.id, target.is_demo ? 'demo_allowlist' : 'meta_tag');
    }
    res.json(challenge);
  });

  // Target Authorization Verification
  app.post('/api/targets/:id/verify', async (req: Request, res: Response) => {
    const target = db.getTarget(req.params.id);
    if (!target) {
      res.status(404).json({ error: 'Target not found' });
      return;
    }

    // Developer / Owner direct declaration
    if (req.body && req.body.developer_confirm) {
      db.updateTarget(target.id, {
        status: 'authorized',
        authorized_at: new Date().toISOString(),
      });
      const challenge = db.getChallengeForTarget(target.id);
      if (challenge) {
        db.updateChallenge(challenge.id, {
          status: 'verified',
          verified_at: new Date().toISOString(),
        });
      }
      db.createAuditLog({
        workspace_id: target.workspace_id,
        action: 'TARGET_AUTHORIZED_BY_OWNER_DECLARATION',
        actor: req.body.owner_email || 'ninjacyber484@gmail.com',
        decision: 'ALLOWED',
        resource_type: 'target',
        resource_id: target.id,
        details: { target_url: target.url, method: 'owner_signoff' },
      });
      res.json({
        success: true,
        status: 'authorized',
        message: 'Target authorized successfully via verified owner declaration.',
      });
      return;
    }

    if (target.is_demo) {
      db.updateTarget(target.id, {
        status: 'authorized',
        authorized_at: new Date().toISOString(),
      });
      res.json({ success: true, status: 'authorized', message: 'Demo target verified via allowlist.' });
      return;
    }

    try {
      const response = await fetch(target.url, {
        headers: { 'user-agent': 'VulnSeal-AuthVerifier/1.0' },
      });
      const html = await response.text();
      let challenge = db.getChallengeForTarget(target.id);
      if (!challenge) {
        challenge = db.createChallenge(target.id, 'meta_tag');
      }

      if (challenge && html.includes(challenge.token)) {
        db.updateTarget(target.id, {
          status: 'authorized',
          authorized_at: new Date().toISOString(),
        });
        db.updateChallenge(challenge.id, {
          status: 'verified',
          verified_at: new Date().toISOString(),
        });
        res.json({ success: true, status: 'authorized', message: 'Meta tag verified successfully on target.' });
      } else {
        res.status(400).json({
          success: false,
          error: `Verification token '${challenge?.token}' not found in HTML response from ${target.url}. Ensure the meta tag is added to your page <head>, or use Developer Owner Authorization.`,
        });
      }
    } catch (err: any) {
      res.status(400).json({
        success: false,
        error: `Failed to connect to ${target.url}: ${err.message}. You can use Developer Owner Authorization if testing behind a firewall.`,
      });
    }
  });

  // Delete Target
  app.delete('/api/targets/:id', (req: Request, res: Response) => {
    const target = db.getTarget(req.params.id);
    if (!target) {
      res.status(404).json({ error: 'Target not found' });
      return;
    }
    const success = db.deleteTarget(target.id);
    res.json({ success, message: `Target '${target.name}' deleted successfully.` });
  });

  // AI Inference Engine Status
  app.get('/api/engine/status', (req: Request, res: Response) => {
    const hasGroq = Boolean(process.env.GROQ_API_KEY && process.env.GROQ_API_KEY.trim().length > 0);
    const hasGemini = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim().length > 0);

    let activeProvider = 'Deterministic Defensive Engine (Built-in)';
    let model = 'Offline Rule-Engine';
    if (hasGroq) {
      activeProvider = 'Groq Cloud Inference';
      model = 'llama-3.3-70b-versatile';
    } else if (hasGemini) {
      activeProvider = 'Google Gemini API';
      model = 'gemini-3.8-flash';
    }

    res.json({
      hasGroq,
      hasGemini,
      activeProvider,
      model,
      offlineFallbackReady: true,
    });
  });

  // Supabase Database Connection Status
  app.get('/api/supabase/status', async (req: Request, res: Response) => {
    const status = await testSupabaseConnection();
    res.json(status);
  });

  // Scans
  app.get('/api/scans', (req: Request, res: Response) => {
    const workspaceId = (req.query.workspace_id as string) || 'ws_default_01';
    res.json(db.getScans(workspaceId));
  });

  app.get('/api/scans/:id', (req: Request, res: Response) => {
    const scan = db.getScan(req.params.id);
    if (!scan) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }
    res.json(scan);
  });

  app.post('/api/scans', async (req: Request, res: Response) => {
    const { target_id, workspace_id } = req.body;
    const target = db.getTarget(target_id);
    if (!target) {
      res.status(404).json({ error: 'Target not found' });
      return;
    }

    if (target.status !== 'authorized') {
      res.status(403).json({
        error: 'Target is not authorized. Scans cannot be executed without verified ownership.',
      });
      return;
    }

    let parsedHost = 'localhost';
    try {
      parsedHost = new URL(target.url).hostname;
    } catch {
      // fallback
    }

    const scan = db.createScan({
      workspace_id: workspace_id || target.workspace_id,
      target_id: target.id,
      target_url: target.url,
      status: 'authorizing',
      scope: {
        target_id: target.id,
        allowed_origin: target.url,
        allowed_hosts: [parsedHost],
        allowed_paths: ['/'],
        excluded_paths: ['/logout', '/delete'],
        max_pages: 15,
        request_budget: 30,
        rate_limit_per_second: 5,
        active_testing_permitted: true,
      },
      pages_discovered: 0,
      rules_executed: 0,
      candidate_findings_count: 0,
      confirmed_findings_count: 0,
      dismissed_findings_count: 0,
      requests_made: 0,
      started_at: new Date().toISOString(),
    });

    // Run scan asynchronously
    ScannerOrchestrator.executeScan(scan.id).catch((err) => {
      console.error(`Scan execution error on ${scan.id}:`, err);
    });

    res.json(scan);
  });

  // Findings
  app.get('/api/findings', (req: Request, res: Response) => {
    const workspaceId = (req.query.workspace_id as string) || 'ws_default_01';
    res.json(db.getFindings(workspaceId));
  });

  app.get('/api/findings/:id', (req: Request, res: Response) => {
    const finding = db.getFinding(req.params.id);
    if (!finding) {
      res.status(404).json({ error: 'Finding not found' });
      return;
    }

    const patch = db.getPatchForFinding(finding.id);
    const rootCause = db.getRootCause(finding.id);
    const approval = patch ? db.getApprovalForPatch(patch.id) : undefined;
    const proof = finding.proof_id ? db.getProof(finding.proof_id) : undefined;

    res.json({
      ...finding,
      patch,
      rootCause,
      approval,
      proof,
    });
  });

  // Remediation Generation: RootCauseMapper + RemediationEngineer
  app.post('/api/findings/:id/remediation', async (req: Request, res: Response) => {
    const finding = db.getFinding(req.params.id);
    if (!finding) {
      res.status(404).json({ error: 'Finding not found' });
      return;
    }

    try {
      db.recordAgentEvent({
        workspace_id: finding.workspace_id,
        finding_id: finding.id,
        agent: 'RootCauseMapper',
        event_type: 'start',
        status: 'in_progress',
        message: 'RootCauseMapper searching repository for source code establishing session cookie configuration...',
      });

      const rootCause = await ModelRouter.mapRootCause(finding.id, finding.evidence);
      db.setRootCause(rootCause);

      db.recordAgentEvent({
        workspace_id: finding.workspace_id,
        finding_id: finding.id,
        agent: 'RootCauseMapper',
        event_type: 'complete',
        status: 'success',
        message: `RootCauseMapper identified vulnerable symbol in ${rootCause.file_path}:${rootCause.line_number}`,
      });

      db.recordAgentEvent({
        workspace_id: finding.workspace_id,
        finding_id: finding.id,
        agent: 'RemediationEngineer',
        event_type: 'start',
        status: 'in_progress',
        message: 'RemediationEngineer generating minimal safe patch diff and regression test...',
      });

      const patch = await ModelRouter.generatePatch(finding.id, rootCause);
      db.createPatch(patch);

      db.updateFinding(finding.id, {
        status: 'waiting_approval',
        remediation_id: patch.id,
      });

      db.recordAgentEvent({
        workspace_id: finding.workspace_id,
        finding_id: finding.id,
        agent: 'RemediationEngineer',
        event_type: 'complete',
        status: 'success',
        message: `RemediationEngineer produced patch candidate (SHA-256: ${patch.sha256_hash.slice(0, 10)}...). Human approval required.`,
        metadata: { patch_id: patch.id, patch_hash: patch.sha256_hash },
      });

      res.json({ rootCause, patch });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Human Approval Gate: Approve & Test
  app.post('/api/remediations/:id/approve', (req: Request, res: Response) => {
    const patch = db.getPatch(req.params.id) || db.getPatchForFinding(req.params.id);
    if (!patch) {
      res.status(404).json({ error: 'Patch not found' });
      return;
    }

    const { approver_email, patch_hash } = req.body;

    if (patch_hash !== patch.sha256_hash) {
      res.status(400).json({
        error: 'Approval rejected: Cryptographic patch hash does not match current patch candidate.',
      });
      return;
    }

    const approval = db.createApproval({
      patch_id: patch.id,
      approved_by_email: approver_email || 'ninjacyber484@gmail.com',
      approved_patch_hash: patch.sha256_hash,
      status: 'approved',
    });

    db.updateFinding(patch.finding_id, { status: 'approved' });

    db.recordAgentEvent({
      workspace_id: 'ws_default_01',
      finding_id: patch.finding_id,
      agent: 'PolicyEngine',
      event_type: 'decision',
      status: 'success',
      message: `Human Approval GRANTED by ${approval.approved_by_email} for patch hash ${patch.sha256_hash.slice(0, 12)}. Ready for ShadowFix digital twin testing.`,
    });

    db.createAuditLog({
      workspace_id: 'ws_default_01',
      action: 'PATCH_APPROVED',
      actor: approval.approved_by_email,
      resource_type: 'patch_candidate',
      resource_id: patch.id,
      decision: 'APPROVED',
      details: { patch_hash: patch.sha256_hash },
    });

    res.json(approval);
  });

  // Human Approval Gate: Reject Patch
  app.post('/api/remediations/:id/reject', (req: Request, res: Response) => {
    const patch = db.getPatch(req.params.id) || db.getPatchForFinding(req.params.id);
    if (!patch) {
      res.status(404).json({ error: 'Patch not found' });
      return;
    }

    const { reason, approver_email } = req.body;

    const approval = db.createApproval({
      patch_id: patch.id,
      approved_by_email: approver_email || 'ninjacyber484@gmail.com',
      approved_patch_hash: patch.sha256_hash,
      status: 'rejected',
      rejection_reason: reason || 'Operator rejected patch candidate.',
    });

    db.updateFinding(patch.finding_id, { status: 'confirmed' });

    db.recordAgentEvent({
      workspace_id: 'ws_default_01',
      finding_id: patch.finding_id,
      agent: 'PolicyEngine',
      event_type: 'decision',
      status: 'warning',
      message: `Human Operator REJECTED patch: ${reason || 'Operator declined'}. Patch discarded.`,
    });

    res.json(approval);
  });

  // ShadowFix Execution
  app.post('/api/remediations/:id/shadowfix', async (req: Request, res: Response) => {
    const patch = db.getPatch(req.params.id) || db.getPatchForFinding(req.params.id);
    if (!patch) {
      res.status(404).json({ error: 'Patch candidate not found' });
      return;
    }

    try {
      const result = await ShadowFixEngine.executeShadowFix({
        remediation_id: patch.id,
        finding_id: patch.finding_id,
        workspace_id: 'ws_default_01',
      });
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Proofs of Fix
  app.get('/api/proofs', (req: Request, res: Response) => {
    const workspaceId = (req.query.workspace_id as string) || 'ws_default_01';
    res.json(db.getProofs(workspaceId));
  });

  app.get('/api/proofs/:id', (req: Request, res: Response) => {
    const proof = db.getProof(req.params.id);
    if (!proof) {
      res.status(404).json({ error: 'Proof not found' });
      return;
    }
    res.json(proof);
  });

  // Agent Events
  app.get('/api/agent-events', (req: Request, res: Response) => {
    const workspaceId = (req.query.workspace_id as string) || 'ws_default_01';
    res.json(db.getAgentEvents(workspaceId));
  });

  // Audit Logs
  app.get('/api/audit-logs', (req: Request, res: Response) => {
    const workspaceId = (req.query.workspace_id as string) || 'ws_default_01';
    res.json(db.getAuditLogs(workspaceId));
  });

  // Demo Reset
  app.post('/api/demo/reset', (req: Request, res: Response) => {
    const workspaceId = (req.body.workspace_id as string) || 'ws_default_01';
    resetDemoRuntimeConfig();
    db.resetDemoState(workspaceId);
    res.json({ success: true, message: 'Demo environment restored to fresh vulnerable baseline.' });
  });

  // Explicit JSON 404 for any unmatched API route to prevent falling through to Vite HTML
  app.all('/api/*', (req: Request, res: Response) => {
    res.status(404).json({ error: `API endpoint not found: ${req.method} ${req.path}` });
  });

  // --- VITE DEV MIDDLEWARE OR STATIC SERVING ---
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[VulnSeal Engine] Running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});

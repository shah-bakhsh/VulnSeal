import { createClient, SupabaseClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseKey =
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_ANON_KEY ||
  process.env.SUPABASE_KEY ||
  '';

export const isSupabaseConfigured = (): boolean => {
  return Boolean(
    supabaseUrl &&
    supabaseUrl.startsWith('https://') &&
    supabaseKey &&
    supabaseKey.length > 10
  );
};

export let supabase: SupabaseClient | null = null;

if (isSupabaseConfigured()) {
  try {
    supabase = createClient(supabaseUrl, supabaseKey, {
      auth: { persistSession: false },
    });
    console.log('[Supabase] Initialized client with project URL:', supabaseUrl);
  } catch (err) {
    console.error('[Supabase] Client initialization failed:', err);
  }
}

export async function testSupabaseConnection(): Promise<{
  connected: boolean;
  configured: boolean;
  url?: string;
  message: string;
}> {
  if (!isSupabaseConfigured() || !supabase) {
    return {
      connected: false,
      configured: false,
      message: 'SUPABASE_URL and SUPABASE_ANON_KEY are not configured in environment.',
    };
  }

  try {
    const { data, error } = await supabase.from('workspaces').select('id, name').limit(1);
    if (error) {
      return {
        connected: false,
        configured: true,
        url: supabaseUrl,
        message: `Connected to Supabase endpoint, but query failed: ${error.message}. Make sure you ran supabase/schema.sql in the Supabase SQL editor.`,
      };
    }
    return {
      connected: true,
      configured: true,
      url: supabaseUrl,
      message: 'Successfully connected to Supabase PostgreSQL database.',
    };
  } catch (err: any) {
    return {
      connected: false,
      configured: true,
      url: supabaseUrl,
      message: `Failed to reach Supabase: ${err.message}`,
    };
  }
}

export async function syncTargetToSupabase(target: any) {
  if (!supabase) return;
  try {
    await supabase.from('targets').upsert({
      id: target.id,
      workspace_id: target.workspace_id || 'ws_default_01',
      url: target.url,
      name: target.name,
      is_demo: target.is_demo ?? false,
      status: target.status,
      authorized_at: target.authorized_at || null,
      security_score: target.security_score ?? 100,
      open_findings_count: target.open_findings_count ?? 0,
      verified_fixes_count: target.verified_fixes_count ?? 0,
      last_scan_at: target.last_scan_at || null,
      created_at: target.created_at || new Date().toISOString(),
    });
  } catch (err) {
    console.warn('[Supabase] Failed to sync target:', err);
  }
}

export async function deleteTargetFromSupabase(targetId: string) {
  if (!supabase) return;
  try {
    await supabase.from('targets').delete().eq('id', targetId);
  } catch (err) {
    console.warn('[Supabase] Failed to delete target:', err);
  }
}

export async function syncScanToSupabase(scan: any) {
  if (!supabase) return;
  try {
    await supabase.from('scans').upsert({
      id: scan.id,
      workspace_id: scan.workspace_id || 'ws_default_01',
      target_id: scan.target_id,
      target_url: scan.target_url,
      status: scan.status,
      start_time: scan.start_time,
      end_time: scan.end_time || null,
      endpoints_crawled: scan.endpoints_crawled || [],
      open_findings_count: scan.open_findings_count || 0,
      findings_detected: scan.findings_detected || [],
      agent_logs: scan.agent_logs || [],
    });
  } catch (err) {
    console.warn('[Supabase] Failed to sync scan:', err);
  }
}

export async function syncFindingToSupabase(finding: any) {
  if (!supabase) return;
  try {
    await supabase.from('findings').upsert({
      id: finding.id,
      workspace_id: finding.workspace_id || 'ws_default_01',
      target_id: finding.target_id,
      scan_id: finding.scan_id || null,
      target_url: finding.target_url,
      endpoint: finding.endpoint,
      method: finding.method || 'GET',
      rule_id: finding.rule_id,
      rule_title: finding.rule_title,
      severity: finding.severity,
      description: finding.description,
      status: finding.status,
      evidence: finding.evidence || null,
      remediation: finding.remediation || null,
      created_at: finding.created_at || new Date().toISOString(),
    });
  } catch (err) {
    console.warn('[Supabase] Failed to sync finding:', err);
  }
}

export async function syncProofToSupabase(proof: any) {
  if (!supabase) return;
  try {
    await supabase.from('proof_of_fixes').upsert({
      id: proof.id,
      workspace_id: proof.workspace_id || 'ws_default_01',
      target_id: proof.target_id,
      finding_id: proof.finding_id,
      rule_id: proof.rule_id,
      rule_title: proof.rule_title,
      target_url: proof.target_url,
      verified_at: proof.verified_at,
      verifier: proof.verifier,
      original_status: proof.original_status,
      patched_status: proof.patched_status,
      patch_hash: proof.patch_hash,
      verification_gates: proof.verification_gates,
      proof_hash: proof.proof_hash,
    });
  } catch (err) {
    console.warn('[Supabase] Failed to sync proof:', err);
  }
}

export async function syncAuditLogToSupabase(log: any) {
  if (!supabase) return;
  try {
    await supabase.from('audit_logs').upsert({
      id: log.id,
      workspace_id: log.workspace_id || 'ws_default_01',
      timestamp: log.timestamp || new Date().toISOString(),
      action: log.action,
      actor: log.actor,
      resource_type: log.resource_type,
      resource_id: log.resource_id,
      decision: log.decision,
      details: log.details || null,
    });
  } catch (err) {
    console.warn('[Supabase] Failed to sync audit log:', err);
  }
}

import { VerificationResult, VerificationVerdict } from './types';
import { db } from './db';

export class IndependentVerifier {
  public static readonly VERIFIER_NAME = 'IndependentVerifier';

  /**
   * Independently evaluates verification criteria.
   * RemediationEngineer cannot approve or verify its own patch.
   */
  public static verifyPatchExecution(params: {
    finding_id: string;
    patch_id: string;
    shadowfix_id: string;
    approved_hash: string;
    applied_patch_hash: string;
    security_replay_passed: boolean;
    regression_tests_passed: boolean;
    has_before_evidence: boolean;
    has_after_evidence: boolean;
    workspace_id: string;
  }): VerificationResult {
    const {
      finding_id,
      patch_id,
      shadowfix_id,
      approved_hash,
      applied_patch_hash,
      security_replay_passed,
      regression_tests_passed,
      has_before_evidence,
      has_after_evidence,
      workspace_id,
    } = params;

    const patchHashMatches =
      Boolean(approved_hash) &&
      Boolean(applied_patch_hash) &&
      approved_hash === applied_patch_hash;

    const evidenceComplete = has_before_evidence && has_after_evidence;

    let verdict: VerificationVerdict = 'FAILED';
    let reason = '';

    if (!patchHashMatches) {
      verdict = 'FAILED';
      reason = 'Cryptographic patch integrity check failed: Applied patch does not match approved SHA-256 hash.';
    } else if (!security_replay_passed) {
      verdict = 'FAILED';
      reason = 'Security replay failed: The original security vulnerability still reproduces after applying the patch.';
    } else if (!regression_tests_passed) {
      verdict = 'REGRESSION_DETECTED';
      reason = 'Application regression detected: Expected application behavior failed in regression test suite.';
    } else if (!evidenceComplete) {
      verdict = 'INCONCLUSIVE';
      reason = 'Evidence is incomplete: Missing before or after verification artifacts.';
    } else {
      verdict = 'VERIFIED';
      reason = 'All verification gates passed: Original vulnerability closed, zero regressions detected, cryptographic patch hash matched.';
    }

    const result = db.createVerification({
      finding_id,
      patch_id,
      shadowfix_id,
      verdict,
      verifier_name: this.VERIFIER_NAME,
      security_replay_match: security_replay_passed,
      regression_passed: regression_tests_passed,
      evidence_complete: evidenceComplete,
      patch_hash_verified: patchHashMatches,
      reason,
    });

    db.recordAgentEvent({
      workspace_id,
      finding_id,
      agent: 'IndependentVerifier',
      event_type: 'decision',
      status: verdict === 'VERIFIED' ? 'success' : 'error',
      message: `IndependentVerifier rendered verdict: ${verdict}. ${reason}`,
      metadata: { verdict, reason, patch_hash_verified: patchHashMatches },
    });

    db.createAuditLog({
      workspace_id,
      action: 'INDEPENDENT_VERIFICATION_COMPLETED',
      actor: 'IndependentVerifier',
      resource_type: 'verification_result',
      resource_id: result.id,
      decision: verdict === 'VERIFIED' ? 'APPROVED' : 'REJECTED',
      details: { verdict, reason },
    });

    return result;
  }
}

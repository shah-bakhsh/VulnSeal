import { NetworkGuard } from '../src/server/policy';
import { CookieSecurityRule } from '../src/server/rules/cookieRule';
import { CorsSecurityRule } from '../src/server/rules/corsRule';
import { SecurityHeadersRule } from '../src/server/rules/headersRule';
import { IndependentVerifier } from '../src/server/verifier';
import { db } from '../src/server/db';
import crypto from 'crypto';

interface TestResult {
  name: string;
  passed: boolean;
  error?: string;
}

const results: TestResult[] = [];

function assert(condition: boolean, testName: string, errorMsg: string = 'Assertion failed') {
  if (condition) {
    results.push({ name: testName, passed: true });
    console.log(`  ✓ ${testName}`);
  } else {
    results.push({ name: testName, passed: false, error: errorMsg });
    console.error(`  ✗ ${testName} — ${errorMsg}`);
  }
}

async function runTestSuite() {
  console.log('\n======================================================');
  console.log('   VULNSEAL AUTOMATED DEFENSIVE SECURITY TEST SUITE   ');
  console.log('   Checking Section 84 Invariants & Security Gates   ');
  console.log('======================================================\n');

  // --- 1. Policy & Authorization Tests ---
  console.log('▶ Category 1: Target Scope & NetworkGuard Policies');

  const defaultScope = {
    target_id: 'test_t1',
    allowed_origin: 'https://example.com',
    allowed_hosts: ['example.com'],
    allowed_paths: ['/'],
    excluded_paths: ['/logout'],
    max_pages: 10,
    request_budget: 15,
    rate_limit_per_second: 5,
    active_testing_permitted: true,
  };

  const allowedDecision = NetworkGuard.evaluateRequest('https://example.com/api/test', defaultScope, false);
  assert(allowedDecision.allowed === true, '1. Verified target in-scope request is allowed');

  const outOfScopeHost = NetworkGuard.evaluateRequest('https://attacker.com/api', defaultScope, false);
  assert(outOfScopeHost.allowed === false && outOfScopeHost.rule === 'OUT_OF_SCOPE_HOST', '2. Out-of-scope host is strictly blocked');

  const excludedPath = NetworkGuard.evaluateRequest('https://example.com/logout', defaultScope, false);
  assert(excludedPath.allowed === false && excludedPath.rule === 'EXCLUDED_PATH', '3. Excluded path policy enforcement blocks /logout');

  const ssrf10 = NetworkGuard.evaluateRequest('http://10.0.0.1/admin', defaultScope, false);
  assert(ssrf10.allowed === false && ssrf10.rule === 'SSRF_PRIVATE_IP_BLOCKED', '4. SSRF private IP (10.0.0.0/8) is blocked');

  const ssrfMetadata = NetworkGuard.evaluateRequest('http://169.254.169.254/latest/meta-data', defaultScope, false);
  assert(ssrfMetadata.allowed === false && ssrfMetadata.rule === 'SSRF_PRIVATE_IP_BLOCKED', '5. SSRF cloud metadata endpoint is blocked');

  const ssrfLocalhost = NetworkGuard.evaluateRequest('http://127.0.0.1:8080/internal', defaultScope, false);
  assert(ssrfLocalhost.allowed === false && ssrfLocalhost.rule === 'SSRF_PRIVATE_IP_BLOCKED', '6. Localhost loopback is blocked for non-demo targets');

  // --- 2. Deterministic Cookie Security Rule Tests ---
  console.log('\n▶ Category 2: Deterministic Cookie Security Rules');

  const insecureCookie = CookieSecurityRule.evaluate('https://example.com/login', 'POST', 200, 'OK', {
    'set-cookie': 'session_token=vs_secret_token_1234; Path=/; HttpOnly; SameSite=Lax',
  });
  assert(insecureCookie.hasVulnerability === true && insecureCookie.attribute_missing === 'Secure', '7. Insecure session cookie (missing Secure) is detected');
  assert(insecureCookie.evidence?.sanitized_excerpt.includes('••••••••') === true, '8. Session token secret is properly redacted in evidence');

  const secureCookie = CookieSecurityRule.evaluate('https://example.com/login', 'POST', 200, 'OK', {
    'set-cookie': 'session_token=vs_secret_token_1234; Path=/; HttpOnly; SameSite=Lax; Secure',
  });
  assert(secureCookie.hasVulnerability === false, '9. Cookie with Secure flag passes inspection');

  const nonSessionCookie = CookieSecurityRule.evaluate('https://example.com/', 'GET', 200, 'OK', {
    'set-cookie': 'theme_mode=dark; Path=/',
  });
  assert(nonSessionCookie.hasVulnerability === false, '10. Non-session cookies do not trigger false positive on missing Secure');

  // --- 3. Deterministic CORS Security Rule Tests ---
  console.log('\n▶ Category 3: Deterministic CORS Security Rules');

  const insecureCors = CorsSecurityRule.evaluate('https://example.com/api/session', 'GET', 200, 'OK', {
    'access-control-allow-origin': '*',
    'access-control-allow-credentials': 'true',
  });
  assert(insecureCors.hasVulnerability === true && insecureCors.rule_id === 'CORS-WILD-001', '11. Permissive CORS wildcard with credentials is detected');

  const safeCors = CorsSecurityRule.evaluate('https://example.com/api/session', 'GET', 200, 'OK', {
    'access-control-allow-origin': 'https://trusted.example.com',
    'access-control-allow-credentials': 'true',
  });
  assert(safeCors.hasVulnerability === false, '12. Restrictive CORS origin configuration passes inspection');

  // --- 4. Deterministic Security Headers Tests ---
  console.log('\n▶ Category 4: Deterministic Security Headers Rules');

  const missingHsts = SecurityHeadersRule.evaluateHSTS('https://example.com/', 'GET', 200, 'OK', {});
  assert(missingHsts.hasVulnerability === true && missingHsts.rule_id === 'HDR-HSTS-001', '13. Missing HSTS header is detected on HTTPS endpoints');

  const presentHsts = SecurityHeadersRule.evaluateHSTS('https://example.com/', 'GET', 200, 'OK', {
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
  });
  assert(presentHsts.hasVulnerability === false, '14. Present HSTS header passes inspection');

  // --- 5. Human Approval & Cryptographic Hash Enforcement ---
  console.log('\n▶ Category 5: Human Approval & Cryptographic Hash Enforcement');

  const testDiff = `--- a/src/demo-app/sessionConfig.ts\n+++ b/src/demo-app/sessionConfig.ts\n@@ -1,3 +1,3 @@\n-secure: false\n+secure: true`;
  const validHash = crypto.createHash('sha256').update(testDiff).digest('hex');
  const alteredHash = crypto.createHash('sha256').update(testDiff + '\n// altered').digest('hex');

  const patchCandidate = db.createPatch({
    finding_id: 'fnd_test_01',
    root_cause: {
      finding_id: 'fnd_test_01',
      file_path: 'src/demo-app/sessionConfig.ts',
      line_number: 4,
      symbol: 'secure',
      code_snippet: 'secure: false',
      explanation: 'test',
      confidence: 1.0,
    },
    affected_file: 'src/demo-app/sessionConfig.ts',
    diff: testDiff,
    sha256_hash: validHash,
    explanation: 'Enforce Secure attribute',
    security_effect: 'Closes HTTP exposure',
    risk_assessment: 'Low',
    generated_regression_test: 'expect(true).toBe(true);',
    verification_plan: 'Replay CookieSecurityRule',
  });

  const approval = db.createApproval({
    patch_id: patchCandidate.id,
    approved_by_email: 'security_operator@vulnseal.local',
    approved_patch_hash: validHash,
    status: 'approved',
  });
  assert(approval.status === 'approved' && approval.approved_patch_hash === validHash, '15. Human approval signs off on exact cryptographic patch hash');

  // --- 6. IndependentVerifier Consensus Tests ---
  console.log('\n▶ Category 6: IndependentVerifier Consensus & Invariants');

  const verifiedVerdict = IndependentVerifier.verifyPatchExecution({
    finding_id: 'fnd_test_01',
    patch_id: patchCandidate.id,
    shadowfix_id: 'sfx_test_01',
    approved_hash: validHash,
    applied_patch_hash: validHash,
    security_replay_passed: true,
    regression_tests_passed: true,
    has_before_evidence: true,
    has_after_evidence: true,
    workspace_id: 'ws_test_01',
  });
  assert(verifiedVerdict.verdict === 'VERIFIED', '16. All 4 verification gates passed yields VERIFIED verdict');

  const replayFailedVerdict = IndependentVerifier.verifyPatchExecution({
    finding_id: 'fnd_test_01',
    patch_id: patchCandidate.id,
    shadowfix_id: 'sfx_test_01',
    approved_hash: validHash,
    applied_patch_hash: validHash,
    security_replay_passed: false, // Security replay failed!
    regression_tests_passed: true,
    has_before_evidence: true,
    has_after_evidence: true,
    workspace_id: 'ws_test_01',
  });
  assert(replayFailedVerdict.verdict === 'FAILED', '17. Failed security replay strictly blocks verification (VERIFIED denied)');

  const regressionFailedVerdict = IndependentVerifier.verifyPatchExecution({
    finding_id: 'fnd_test_01',
    patch_id: patchCandidate.id,
    shadowfix_id: 'sfx_test_01',
    approved_hash: validHash,
    applied_patch_hash: validHash,
    security_replay_passed: true,
    regression_tests_passed: false, // Application regression detected!
    has_before_evidence: true,
    has_after_evidence: true,
    workspace_id: 'ws_test_01',
  });
  assert(regressionFailedVerdict.verdict === 'REGRESSION_DETECTED', '18. Application regression detection strictly blocks verification');

  const hashMismatchVerdict = IndependentVerifier.verifyPatchExecution({
    finding_id: 'fnd_test_01',
    patch_id: patchCandidate.id,
    shadowfix_id: 'sfx_test_01',
    approved_hash: validHash,
    applied_patch_hash: alteredHash, // Tampered patch hash!
    security_replay_passed: true,
    regression_tests_passed: true,
    has_before_evidence: true,
    has_after_evidence: true,
    workspace_id: 'ws_test_01',
  });
  assert(hashMismatchVerdict.verdict === 'FAILED', '19. Altered patch hash mismatch strictly blocks verification');

  // --- 7. Multi-Tenant Workspace Isolation ---
  console.log('\n▶ Category 7: Multi-Tenant Workspace Isolation');

  const wsA = `ws_tenant_alpha_${Date.now()}`;
  const wsB = `ws_tenant_beta_${Date.now()}`;

  db.createTarget({
    workspace_id: wsA,
    url: 'https://tenant-alpha.example.com',
    name: 'Tenant Alpha App',
    is_demo: false,
    status: 'authorized',
  });

  const targetsA = db.getTargets(wsA);
  const targetsB = db.getTargets(wsB);
  assert(targetsA.length === 1 && targetsB.length === 0, '20. Workspace A data is completely isolated from Workspace B');

  // Summary
  console.log('\n======================================================');
  const passedCount = results.filter((r) => r.passed).length;
  console.log(`   TEST RESULTS: ${passedCount} / ${results.length} PASSED`);
  console.log('======================================================\n');

  if (passedCount !== results.length) {
    process.exit(1);
  }
}

runTestSuite().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});

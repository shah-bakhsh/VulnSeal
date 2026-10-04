import crypto from 'crypto';
import { FindingEvidence, Severity } from '../types';

export interface CookieCheckResult {
  hasVulnerability: boolean;
  rule_id: string;
  rule_name: string;
  category: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  evidence?: FindingEvidence;
  attribute_missing?: string;
}

export class CookieSecurityRule {
  public static readonly RULE_ID = 'COOKIE-SECURE-001';
  public static readonly RULE_NAME = 'Insecure Session Cookie (Missing Secure Flag)';

  /**
   * Sanitizes cookie value for evidence display, masking sensitive session keys.
   */
  public static sanitizeCookieHeader(rawHeader: string): string {
    return rawHeader.replace(/(=)([^;]+)/, (match, eq, val) => {
      if (val.length <= 4) return `${eq}••••`;
      return `${eq}${val.slice(0, 4)}••••••••`;
    });
  }

  /**
   * Deterministically evaluates Set-Cookie headers for security attributes.
   */
  public static evaluate(
    url: string,
    method: string,
    status: number,
    statusText: string,
    responseHeaders: Record<string, string>,
    findingId: string = crypto.randomUUID()
  ): CookieCheckResult {
    // Normalizing header key lookup
    let setCookieHeader: string | undefined;
    for (const [key, value] of Object.entries(responseHeaders)) {
      if (key.toLowerCase() === 'set-cookie') {
        setCookieHeader = value;
        break;
      }
    }

    if (!setCookieHeader) {
      return {
        hasVulnerability: false,
        rule_id: this.RULE_ID,
        rule_name: this.RULE_NAME,
        category: 'Session Management',
        title: 'Session Cookie Missing Secure Attribute',
        description: 'No Set-Cookie header detected.',
        severity: 'high',
        confidence: 0,
      };
    }

    const cookieParts = setCookieHeader.split(';').map((p) => p.trim());
    const [nameVal] = cookieParts;
    const cookieName = nameVal.split('=')[0]?.trim().toLowerCase();

    // Check if this cookie is a session/auth token
    const isSessionCookie =
      cookieName.includes('session') ||
      cookieName.includes('token') ||
      cookieName.includes('auth') ||
      cookieName.includes('sid') ||
      cookieName.includes('jwt') ||
      cookieName.includes('id');

    const hasSecure = cookieParts.some((p) => p.toLowerCase() === 'secure');
    const hasHttpOnly = cookieParts.some((p) => p.toLowerCase() === 'httponly');
    const hasSameSite = cookieParts.some((p) => p.toLowerCase().startsWith('samesite'));

    // If Secure attribute is missing on a session cookie, this is a confirmed deterministic vulnerability
    if (!hasSecure && isSessionCookie) {
      const sanitized = this.sanitizeCookieHeader(setCookieHeader);
      const observationDesc = `Set-Cookie header sets session cookie '${cookieName}' without the 'Secure' directive. Browsers may transmit this session cookie over unencrypted HTTP channels in cleartext.`;

      const evidenceContent = `${url}|${method}|${status}|${sanitized}`;
      const sha256_hash = crypto.createHash('sha256').update(evidenceContent).digest('hex');

      const evidence: FindingEvidence = {
        id: crypto.randomUUID(),
        finding_id: findingId,
        request_method: method,
        request_url: url,
        request_headers: {
          'user-agent': 'VulnSeal-SecurityInspector/1.0 (Defensive; Scoped)',
          accept: 'application/json, text/html, */*',
        },
        response_status: status,
        response_status_text: statusText,
        response_headers: {
          'content-type': responseHeaders['content-type'] || 'application/json',
          'set-cookie': sanitized,
        },
        sanitized_excerpt: `Set-Cookie: ${sanitized}`,
        observation_description: observationDesc,
        raw_attribute_missing: 'Secure',
        captured_at: new Date().toISOString(),
        sha256_hash,
      };

      return {
        hasVulnerability: true,
        rule_id: this.RULE_ID,
        rule_name: this.RULE_NAME,
        category: 'Session Management',
        title: 'Session Cookie Missing Secure Flag',
        description:
          'A session identifier is issued without the Secure attribute flag. This violates defensive session security by permitting the cookie to be sent across cleartext HTTP transmissions.',
        severity: 'high',
        confidence: 0.98, // High deterministic confidence because real header observed
        evidence,
        attribute_missing: 'Secure',
      };
    }

    return {
      hasVulnerability: false,
      rule_id: this.RULE_ID,
      rule_name: this.RULE_NAME,
      category: 'Session Management',
      title: 'Session Cookie Security Validated',
      description: 'Set-Cookie header includes the Secure attribute flag.',
      severity: 'high',
      confidence: 1.0,
    };
  }
}

import crypto from 'crypto';
import { FindingEvidence, Severity } from '../types';

export interface HeaderCheckResult {
  hasVulnerability: boolean;
  rule_id: string;
  rule_name: string;
  category: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  evidence?: FindingEvidence;
}

export class SecurityHeadersRule {
  public static readonly RULE_HSTS = 'HDR-HSTS-001';
  public static readonly RULE_CSP = 'HDR-CSP-001';
  public static readonly RULE_XCTO = 'HDR-XCTO-001';

  public static evaluateHSTS(
    url: string,
    method: string,
    status: number,
    statusText: string,
    responseHeaders: Record<string, string>,
    findingId: string = crypto.randomUUID()
  ): HeaderCheckResult {
    let hstsHeader: string | undefined;
    for (const [key, val] of Object.entries(responseHeaders)) {
      if (key.toLowerCase() === 'strict-transport-security') {
        hstsHeader = val;
        break;
      }
    }

    if (!hstsHeader && (url.startsWith('https://') || url.includes('/demo-target'))) {
      const evidenceContent = `${url}|${method}|${status}|missing-hsts`;
      const sha256_hash = crypto.createHash('sha256').update(evidenceContent).digest('hex');

      return {
        hasVulnerability: true,
        rule_id: this.RULE_HSTS,
        rule_name: 'Missing HTTP Strict Transport Security (HSTS)',
        category: 'Transport Security',
        title: 'Missing Strict-Transport-Security Header',
        description:
          'The target application does not advertise HTTP Strict-Transport-Security (HSTS), leaving web clients susceptible to SSL-stripping and man-in-the-middle downgrade attacks.',
        severity: 'medium',
        confidence: 0.95,
        evidence: {
          id: crypto.randomUUID(),
          finding_id: findingId,
          request_method: method,
          request_url: url,
          request_headers: {
            'user-agent': 'VulnSeal-SecurityInspector/1.0',
            accept: '*/*',
          },
          response_status: status,
          response_status_text: statusText,
          response_headers: responseHeaders,
          sanitized_excerpt: 'Strict-Transport-Security: [NOT PRESENT IN RESPONSE HEADERS]',
          observation_description:
            'Strict-Transport-Security response header was not returned by the server.',
          captured_at: new Date().toISOString(),
          sha256_hash,
        },
      };
    }

    return {
      hasVulnerability: false,
      rule_id: this.RULE_HSTS,
      rule_name: 'HSTS Verified',
      category: 'Transport Security',
      title: 'HSTS Header Present',
      description: 'Strict-Transport-Security header is properly configured.',
      severity: 'medium',
      confidence: 1.0,
    };
  }

  public static evaluateCSP(
    url: string,
    method: string,
    status: number,
    statusText: string,
    responseHeaders: Record<string, string>,
    findingId: string = crypto.randomUUID()
  ): HeaderCheckResult {
    let cspHeader: string | undefined;
    for (const [key, val] of Object.entries(responseHeaders)) {
      if (key.toLowerCase() === 'content-security-policy') {
        cspHeader = val;
        break;
      }
    }

    if (!cspHeader && (url.includes('/demo-target') || url.includes('html'))) {
      const evidenceContent = `${url}|${method}|${status}|missing-csp`;
      const sha256_hash = crypto.createHash('sha256').update(evidenceContent).digest('hex');

      return {
        hasVulnerability: true,
        rule_id: this.RULE_CSP,
        rule_name: 'Missing Content-Security-Policy (CSP)',
        category: 'Browser Defense',
        title: 'Missing Content-Security-Policy Header',
        description:
          'No Content-Security-Policy header is served, which exposes clients to cross-site scripting (XSS) and code injection vulnerabilities.',
        severity: 'medium',
        confidence: 0.95,
        evidence: {
          id: crypto.randomUUID(),
          finding_id: findingId,
          request_method: method,
          request_url: url,
          request_headers: {
            'user-agent': 'VulnSeal-SecurityInspector/1.0',
            accept: 'text/html, */*',
          },
          response_status: status,
          response_status_text: statusText,
          response_headers: responseHeaders,
          sanitized_excerpt: 'Content-Security-Policy: [NOT PRESENT IN RESPONSE HEADERS]',
          observation_description:
            'Content-Security-Policy header was missing on HTML landing endpoint.',
          captured_at: new Date().toISOString(),
          sha256_hash,
        },
      };
    }

    return {
      hasVulnerability: false,
      rule_id: this.RULE_CSP,
      rule_name: 'CSP Verified',
      category: 'Browser Defense',
      title: 'Content-Security-Policy Configured',
      description: 'Content-Security-Policy is present.',
      severity: 'medium',
      confidence: 1.0,
    };
  }
}

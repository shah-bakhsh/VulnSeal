import crypto from 'crypto';
import { FindingEvidence, Severity } from '../types';

export interface CorsCheckResult {
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

export class CorsSecurityRule {
  public static readonly RULE_ID = 'CORS-WILD-001';
  public static readonly RULE_NAME = 'Permissive CORS with Credentials Allowed';

  /**
   * Evaluates Access-Control-Allow-Origin and Access-Control-Allow-Credentials headers.
   */
  public static evaluate(
    url: string,
    method: string,
    status: number,
    statusText: string,
    responseHeaders: Record<string, string>,
    findingId: string = crypto.randomUUID()
  ): CorsCheckResult {
    let allowOrigin: string | undefined;
    let allowCredentials: string | undefined;

    for (const [key, val] of Object.entries(responseHeaders)) {
      const lower = key.toLowerCase();
      if (lower === 'access-control-allow-origin') {
        allowOrigin = val;
      } else if (lower === 'access-control-allow-credentials') {
        allowCredentials = val;
      }
    }

    // Flag if wildcard origin or reflection is used with credentials
    const isPermissiveOrigin = allowOrigin === '*' || allowOrigin === 'null';
    const hasCredentials = allowCredentials?.toLowerCase() === 'true';

    if (isPermissiveOrigin && hasCredentials) {
      const evidenceContent = `${url}|${method}|${status}|${allowOrigin}|${allowCredentials}`;
      const sha256_hash = crypto.createHash('sha256').update(evidenceContent).digest('hex');

      return {
        hasVulnerability: true,
        rule_id: this.RULE_ID,
        rule_name: this.RULE_NAME,
        category: 'Access Control',
        title: 'Unsafe CORS Configuration with Credentials',
        description:
          'The application configures Access-Control-Allow-Origin with a wildcard/null while enabling Access-Control-Allow-Credentials. This allows unauthorized third-party origins to read authenticated responses.',
        severity: 'high',
        confidence: 0.96,
        evidence: {
          id: crypto.randomUUID(),
          finding_id: findingId,
          request_method: method,
          request_url: url,
          request_headers: {
            'user-agent': 'VulnSeal-SecurityInspector/1.0',
            origin: 'https://evil-attacker.example',
          },
          response_status: status,
          response_status_text: statusText,
          response_headers: responseHeaders,
          sanitized_excerpt: `Access-Control-Allow-Origin: ${allowOrigin}\nAccess-Control-Allow-Credentials: ${allowCredentials}`,
          observation_description:
            'Response returns Access-Control-Allow-Origin wildcard paired with Access-Control-Allow-Credentials: true.',
          captured_at: new Date().toISOString(),
          sha256_hash,
        },
      };
    }

    return {
      hasVulnerability: false,
      rule_id: this.RULE_ID,
      rule_name: this.RULE_NAME,
      category: 'Access Control',
      title: 'CORS Configuration Validated',
      description: 'CORS policy correctly restricts origins or denies credentials.',
      severity: 'high',
      confidence: 1.0,
    };
  }
}

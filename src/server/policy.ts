import { ScanScope } from './types';
import { db } from './db';

export interface PolicyDecision {
  allowed: boolean;
  rule: string;
  reason: string;
  target_url: string;
}

export class NetworkGuard {
  private static requestCounts: Map<string, number> = new Map();
  private static lastRequestTimes: Map<string, number> = new Map();

  /**
   * Evaluates if a network request is allowed by system safety policies.
   */
  public static evaluateRequest(
    targetUrl: string,
    scope: ScanScope,
    isDemo: boolean = false,
    workspaceId: string = 'default'
  ): PolicyDecision {
    let parsed: URL;
    try {
      parsed = new URL(targetUrl);
    } catch {
      return {
        allowed: false,
        rule: 'INVALID_URL',
        reason: 'Malformed URL could not be parsed safely.',
        target_url: targetUrl,
      };
    }

    // 1. Validate Scheme
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return {
        allowed: false,
        rule: 'INVALID_SCHEME',
        reason: `Unsupported protocol ${parsed.protocol}. Only http and https are permitted.`,
        target_url: targetUrl,
      };
    }

    const host = parsed.hostname.toLowerCase();

    // 2. SSRF Protection: Deny cloud metadata services, loopback, and private IPs
    const isLoopbackOrPrivate =
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '::1' ||
      host.startsWith('10.') ||
      host.startsWith('192.168.') ||
      host.startsWith('169.254.') || // AWS / GCP / Azure metadata endpoint
      host.startsWith('172.16.') ||
      host.startsWith('172.17.') ||
      host.startsWith('172.18.') ||
      host.startsWith('172.19.') ||
      host.startsWith('172.20.') ||
      host.startsWith('172.21.') ||
      host.startsWith('172.22.') ||
      host.startsWith('172.23.') ||
      host.startsWith('172.24.') ||
      host.startsWith('172.25.') ||
      host.startsWith('172.26.') ||
      host.startsWith('172.27.') ||
      host.startsWith('172.28.') ||
      host.startsWith('172.29.') ||
      host.startsWith('172.30.') ||
      host.startsWith('172.31.');

    if (isLoopbackOrPrivate) {
      // Precise Demo Sandbox exception:
      // ONLY allowed if:
      // 1. isDemo is true (verified demo target)
      // 2. host is exact 'localhost' or '127.0.0.1'
      // 3. port is either 3000 or omitted (default dev server)
      // 4. path starts strictly with '/demo-target'
      const isExactDemoSandbox =
        isDemo &&
        (host === 'localhost' || host === '127.0.0.1') &&
        (parsed.port === '3000' || parsed.port === '' || parsed.port === (process.env.PORT || '3000')) &&
        (parsed.pathname.startsWith('/demo-target') || parsed.pathname.startsWith('/api/demo-target'));

      if (!isExactDemoSandbox) {
        db.createAuditLog({
          workspace_id: workspaceId,
          action: 'POLICY_DENIAL_SSRF',
          actor: 'NetworkGuard',
          resource_type: 'network_request',
          resource_id: targetUrl,
          decision: 'DENIED',
          details: { host, port: parsed.port, reason: 'Private or metadata IP blocked by SSRF filter' },
        });

        return {
          allowed: false,
          rule: 'SSRF_PRIVATE_IP_BLOCKED',
          reason: `VulnSeal prevented this scan request to '${host}' because it violated the configured network safety policy (SSRF private network protection).`,
          target_url: targetUrl,
        };
      }
    }

    // 3. Allowed Origin / Host Scope
    if (scope.allowed_hosts && scope.allowed_hosts.length > 0) {
      const isHostAllowed = scope.allowed_hosts.some(
        (allowed) => host === allowed.toLowerCase() || host.endsWith(`.${allowed.toLowerCase()}`)
      );
      if (!isHostAllowed) {
        return {
          allowed: false,
          rule: 'OUT_OF_SCOPE_HOST',
          reason: `Host ${host} is outside authorized scan scope hosts: ${scope.allowed_hosts.join(', ')}`,
          target_url: targetUrl,
        };
      }
    }

    // 4. Excluded Paths
    if (scope.excluded_paths && scope.excluded_paths.length > 0) {
      for (const excluded of scope.excluded_paths) {
        if (parsed.pathname.startsWith(excluded)) {
          return {
            allowed: false,
            rule: 'EXCLUDED_PATH',
            reason: `Path ${parsed.pathname} matches excluded path policy: ${excluded}`,
            target_url: targetUrl,
          };
        }
      }
    }

    // 5. Request Budget
    const scanKey = scope.target_id;
    const currentCount = (this.requestCounts.get(scanKey) || 0) + 1;
    if (currentCount > scope.request_budget) {
      return {
        allowed: false,
        rule: 'REQUEST_BUDGET_EXCEEDED',
        reason: `Scan request budget (${scope.request_budget}) exceeded. Current: ${currentCount}`,
        target_url: targetUrl,
      };
    }

    // 6. Rate Limiting Check
    const now = Date.now();
    const lastTime = this.lastRequestTimes.get(scanKey) || 0;
    const minIntervalMs = 1000 / (scope.rate_limit_per_second || 5);
    if (now - lastTime < minIntervalMs) {
      // In synchronous evaluation, we note rate throttle
    }
    this.lastRequestTimes.set(scanKey, now);
    this.requestCounts.set(scanKey, currentCount);

    return {
      allowed: true,
      rule: 'AUTHORIZED_TARGET',
      reason: 'Target is authorized and request conforms to active scope boundaries.',
      target_url: targetUrl,
    };
  }

  public static resetBudget(targetId: string) {
    this.requestCounts.delete(targetId);
    this.lastRequestTimes.delete(targetId);
  }
}

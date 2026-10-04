import { Router, Request, Response } from 'express';
import { sessionCookieOptions } from '../demo-app/sessionConfig';
import { corsOptions } from '../demo-app/corsConfig';

export const demoRouter = Router();

// In-memory runtime state for the demo target, with support for live isolated twin testing
let demoSessionConfig = { ...sessionCookieOptions };
let demoCorsConfig = { ...corsOptions };

export function setDemoRuntimeSecureFlag(secure: boolean) {
  demoSessionConfig.secure = secure;
}

export function setDemoRuntimeCorsOrigin(origin: string) {
  demoCorsConfig.origin = origin;
}

export function getDemoRuntimeConfig() {
  return { session: demoSessionConfig, cors: demoCorsConfig };
}

export function resetDemoRuntimeConfig() {
  demoSessionConfig = {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: false, // restore vulnerable baseline
    maxAge: 86400 * 1000,
  };
  demoCorsConfig = {
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  };
}

// 1. Homepage with ownership challenge meta tag
demoRouter.get('/', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VulnSeal Vulnerable Demo Banking Portal</title>
  <!-- Target Ownership Verification Meta Tag -->
  <meta name="vulnseal-verification" content="vs_token_demo_valid_99a8">
</head>
<body>
  <h1>VulnSeal Deliberately Vulnerable Demo Application</h1>
  <p>Authorized defensive test application for automated security remediation.</p>
  <nav>
    <a href="/demo-target/login">Login Endpoint</a> |
    <a href="/demo-target/api/session">Session API</a> |
    <a href="/demo-target/api/profile">Profile API</a> |
    <a href="/demo-target/api/health">Health Check</a>
  </nav>
</body>
</html>`);
});

// 2. Login endpoint that sets the session cookie
demoRouter.all('/login', (req: Request, res: Response) => {
  // Construct real Set-Cookie header using current demo configuration
  const parts = [
    `session_token=vs_sess_demo_7c3a9f1b`,
    'Path=/',
    `Max-Age=${demoSessionConfig.maxAge / 1000}`,
  ];

  if (demoSessionConfig.httpOnly) parts.push('HttpOnly');
  if (demoSessionConfig.sameSite) parts.push(`SameSite=${demoSessionConfig.sameSite}`);
  if (demoSessionConfig.secure) parts.push('Secure');

  const cookieHeader = parts.join('; ');
  res.setHeader('Set-Cookie', cookieHeader);
  res.setHeader('Content-Type', 'application/json');

  res.json({
    status: 'authenticated',
    user: 'demo_developer@vulnseal.local',
    role: 'administrator',
    session_id: 'vs_sess_demo_7c3a9f1b',
    cookie_issued: cookieHeader,
    security_metadata: {
      secure_flag_enabled: demoSessionConfig.secure,
      http_only_enabled: demoSessionConfig.httpOnly,
      same_site_policy: demoSessionConfig.sameSite,
    },
  });
});

// 3. Authenticated session check API
demoRouter.get('/api/session', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', demoCorsConfig.origin);
  res.setHeader('Access-Control-Allow-Credentials', String(demoCorsConfig.credentials));
  res.json({
    active: true,
    user_id: 'usr_demo_4412',
    expires_in: 86400,
    secure_mode: demoSessionConfig.secure,
    cors_origin: demoCorsConfig.origin,
  });
});

// 4. Authenticated profile API
demoRouter.get('/api/profile', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', demoCorsConfig.origin);
  res.setHeader('Access-Control-Allow-Credentials', String(demoCorsConfig.credentials));
  res.json({
    username: 'defensive_dev',
    email: 'dev@vulnseal.local',
    workspace: 'SecOps-Demo-Team',
  });
});

// 5. Health check
demoRouter.get('/api/health', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'application/json');
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

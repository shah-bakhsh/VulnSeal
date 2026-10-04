/**
 * VulnSeal Deliberately Vulnerable Demo Application
 * Session Configuration
 *
 * NOTE: Intentionally missing the 'secure' flag to demonstrate
 * defensive vulnerability detection and verified automated repair.
 */
export const sessionCookieOptions = {
  httpOnly: true,
  sameSite: 'lax' as const,
  secure: false, // Insecure: missing secure transport requirement
  maxAge: 86400 * 1000,
};

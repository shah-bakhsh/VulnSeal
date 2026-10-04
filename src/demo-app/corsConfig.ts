/**
 * VulnSeal Demo Application CORS Configuration
 *
 * NOTE: Intentionally permissive for security scanning demonstration.
 */
export const corsOptions = {
  origin: '*' as string, // Insecure when credentials: true
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
};

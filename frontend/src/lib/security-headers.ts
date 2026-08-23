/**
 * Security headers applied by the proxy to every console response.
 * Pure string map so it is trivially unit-testable.
 *
 * CSP note: Next.js App Router requires inline scripts for hydration
 * bootstrapping; 'unsafe-inline' for script-src is a known trade-off.
 */

export function securityHeaders(isProd: boolean, isHttps: boolean): Record<string, string> {
  const cspParts = [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline'${isProd ? "" : " 'unsafe-eval'"}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
  ];
  const headers: Record<string, string> = {
    "Content-Security-Policy": cspParts.join("; "),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  };
  if (isHttps) {
    headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains";
  }
  return headers;
}

export function applySecurityHeaders(
  response: Response,
  isProd: boolean,
  isHttps: boolean
): Response {
  for (const [name, value] of Object.entries(securityHeaders(isProd, isHttps))) {
    response.headers.set(name, value);
  }
  return response;
}

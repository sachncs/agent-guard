/**
 * Externally visible origin (proxy/CDN aware). Falls back to the request
 * host when no forwarded headers exist.
 */
/** Resolve the externally visible origin for building absolute redirect URLs. */
export function publicOrigin(request: Request): string {
  const proto = request.headers.get("x-forwarded-proto")?.split(",")[0].trim();
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  if (proto && host) return `${proto}://${host}`;
  return new URL(request.url).origin;
}

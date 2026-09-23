/**
 * Resolve the request origin without trusting spoofable forwarded headers.
 * A reverse proxy must rewrite the request URL/host before it reaches the
 * app, or configure a deployment-specific trusted-origin mechanism.
 */
export function publicOrigin(request: Request): string {
  return new URL(request.url).origin;
}

/** Require an explicit browser same-origin signal for state-changing routes. */
export function isSameOriginRequest(request: Request, trustProxyHeaders = false): boolean {
  const origin = request.headers.get("origin");
  if (origin) {
    try {
      const expectedOrigin = trustProxyHeaders ? trustedProxyOrigin(request) : publicOrigin(request);
      return expectedOrigin !== undefined && new URL(origin).origin === expectedOrigin;
    } catch {
      return false;
    }
  }
  return request.headers.get("sec-fetch-site") === "same-origin";
}

function trustedProxyOrigin(request: Request): string | undefined {
  const host = request.headers.get("x-forwarded-host");
  const protocol = request.headers.get("x-forwarded-proto");
  if (!host || host.includes(",") || !protocol || protocol.includes(",")) return undefined;
  if (protocol !== "http" && protocol !== "https") return undefined;
  try {
    const url = new URL(`${protocol}://${host}`);
    if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) return undefined;
    return url.origin;
  } catch {
    return undefined;
  }
}

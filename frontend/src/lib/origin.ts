/**
 * Resolve the request origin without trusting spoofable forwarded headers.
 * A reverse proxy must rewrite the request URL/host before it reaches the
 * app, or configure a deployment-specific trusted-origin mechanism.
 */
export function publicOrigin(request: Request): string {
  return new URL(request.url).origin;
}

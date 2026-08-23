/**
 * Route-handler helpers: resolve the console session from the request's
 * Cookie header and enforce roles. Handlers never trust client headers.
 */

import type { SessionClaims } from "./session";
import { SESSION_COOKIE, parseCookieHeader, verifySession } from "./session";

export function sessionFromRequest(
  secret: Uint8Array,
  request: Request
): Promise<SessionClaims | null> {
  const cookies = parseCookieHeader(request.headers.get("cookie"));
  return verifySession(secret, cookies[SESSION_COOKIE]).then((r) =>
    r.ok ? r.claims : null
  );
}

export function unauthorized(): Response {
  return Response.json(
    { error: "authentication required", kind: "unauthenticated" },
    { status: 401 }
  );
}

export function forbidden(): Response {
  return Response.json(
    { error: "administrator role required", kind: "forbidden" },
    { status: 403 }
  );
}

export async function requireViewer(
  secret: Uint8Array,
  request: Request
): Promise<SessionClaims | Response> {
  const session = await sessionFromRequest(secret, request);
  return session ?? unauthorized();
}

export async function requireAdmin(
  secret: Uint8Array,
  request: Request
): Promise<SessionClaims | Response> {
  const session = await sessionFromRequest(secret, request);
  if (!session) return unauthorized();
  return session.admin ? session : forbidden();
}

export function isResponse(v: unknown): v is Response {
  return v instanceof Response;
}

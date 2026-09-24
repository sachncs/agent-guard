/**
 * Route-handler helpers: resolve the console session from the request's
 * Cookie header and enforce roles. Handlers never trust client headers.
 */

import type { SessionClaims, VerifyResult } from "./session";
import { SESSION_COOKIE, parseCookieHeader, verifySession } from "./session";
import type { SessionStore } from "./session_store";

/** Resolve authentication without conflating invalid credentials and outages. */
export function sessionFromRequest(
  secret: Uint8Array,
  request: Request,
  store?: SessionStore,
): Promise<VerifyResult<SessionClaims>> {
  const cookies = parseCookieHeader(request.headers.get("cookie"));
  return verifySession(secret, cookies[SESSION_COOKIE], store);
}

/** 401 JSON response for missing/invalid sessions. */
export function unauthorized(): Response {
  return Response.json(
    { error: "authentication required", kind: "unauthenticated" },
    { status: 401 }
  );
}

/** 503 response when authentication cannot be verified because storage is down. */
export function sessionStoreUnavailable(): Response {
  return Response.json(
    { error: "session verification is temporarily unavailable", kind: "session_store_unavailable" },
    { status: 503, headers: { "Cache-Control": "no-store" } },
  );
}

/** 403 JSON response for authenticated non-admin requests. */
export function forbidden(): Response {
  return Response.json(
    { error: "administrator role required", kind: "forbidden" },
    { status: 403 }
  );
}

/** Enforce authentication; returns claims or a 401 Response. */
export async function requireViewer(
  secret: Uint8Array,
  request: Request,
  store?: SessionStore,
): Promise<SessionClaims | Response> {
  const session = await sessionFromRequest(secret, request, store);
  if (session.ok) return session.claims;
  return session.reason === "store_unavailable" ? sessionStoreUnavailable() : unauthorized();
}

/** Enforce the admin role; returns claims, a 401 or a 403 Response. */
export async function requireAdmin(
  secret: Uint8Array,
  request: Request,
  store?: SessionStore,
): Promise<SessionClaims | Response> {
  const session = await sessionFromRequest(secret, request, store);
  if (!session.ok) {
    return session.reason === "store_unavailable" ? sessionStoreUnavailable() : unauthorized();
  }
  return session.claims.admin ? session.claims : forbidden();
}

/** Narrow the union returned by {@link requireViewer}/{@link requireAdmin}. */
export function isResponse(v: unknown): v is Response {
  return v instanceof Response;
}

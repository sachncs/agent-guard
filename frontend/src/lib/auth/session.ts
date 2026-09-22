/**
 * Console session tokens: compact JWS (HS256 via jose) stored in an
 * HttpOnly cookie. Pure module (no Next imports) so it is unit-testable
 * and edge-runtime safe.
 */

import { SignJWT, jwtVerify } from "jose";
import type { SessionStore } from "./session_store";

export const SESSION_COOKIE = "ag_session";
export const OIDC_STATE_COOKIE = "ag_oidc";
export const SESSION_TTL_SECONDS = 8 * 60 * 60;
export const STATE_TTL_SECONDS = 10 * 60;

/** Claims carried by a console session cookie. */
export interface SessionClaims {
  sub: string;
  email?: string;
  name?: string;
  /** Admin role was resolved at login time; handlers trust this flag. */
  admin: boolean;
}

/** Sign a console session JWT (HS256) with the configured TTL. */
export async function signSession(
  secret: Uint8Array,
  claims: SessionClaims,
  ttlSeconds: number = SESSION_TTL_SECONDS,
  store?: SessionStore,
): Promise<string> {
  const id = crypto.randomUUID();
  if (store) await store.put(id, claims, ttlSeconds);
  return new SignJWT({ ...claims })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer("agentguard-console")
    .setAudience("agentguard-console")
    .setJti(id)
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + ttlSeconds)
    .sign(secret);
}

/** Discriminated result of a session verification. */
export type VerifyResult<T> = { ok: true; claims: T } | { ok: false };

/** Verify a session JWT; returns `{ok: false}` for missing/invalid/expired tokens. */
export async function verifySession(
  secret: Uint8Array,
  token: string | undefined,
  store?: SessionStore,
): Promise<VerifyResult<SessionClaims>> {
  if (!token) return { ok: false };
  try {
    const { payload } = await jwtVerify(token, secret, {
      issuer: "agentguard-console",
      audience: "agentguard-console",
      algorithms: ["HS256"],
    });
    if (
      typeof payload.sub !== "string" ||
      typeof payload.admin !== "boolean"
    ) {
      return { ok: false };
    }
    const claims = {
      sub: payload.sub,
      email: typeof payload.email === "string" ? payload.email : undefined,
      name: typeof payload.name === "string" ? payload.name : undefined,
      admin: payload.admin,
    };
    if (store) {
      if (typeof payload.jti !== "string") return { ok: false };
      const stored = await store.get(payload.jti);
      if (!stored) return { ok: false };
      return { ok: true, claims: stored };
    }
    return {
      ok: true,
      claims,
    };
  } catch {
    return { ok: false };
  }
}

/** Revoke a server-side session record when a user logs out. */
export async function revokeSession(
  secret: Uint8Array,
  token: string | undefined,
  store?: SessionStore,
): Promise<void> {
  if (!store || !token) return;
  try {
    const { payload } = await jwtVerify(token, secret, {
      issuer: "agentguard-console",
      audience: "agentguard-console",
      algorithms: ["HS256"],
    });
    if (typeof payload.jti === "string") await store.delete(payload.jti);
  } catch {
    // Logout is idempotent; clearing the cookie is sufficient for invalid JWTs.
  }
}

/** Minimal RFC 6265 parser for the request Cookie header. */
export function parseCookieHeader(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    let value = part.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    if (name) {
      try {
        out[name] = decodeURIComponent(value);
      } catch {
        // Ignore malformed cookie encoding rather than turning an attacker
        // controlled Cookie header into a route-level 500.
      }
    }
  }
  return out;
}

/** Attributes for {@link serializeSetCookie}. */
export interface CookieOptions {
  maxAge?: number;
  secure: boolean;
}

/**
 * Serialize a Set-Cookie value without Next runtime dependencies so both
 * proxy and route handlers emit identical attributes.
 */
export function serializeSetCookie(
  name: string,
  value: string,
  options: CookieOptions
): string {
  const attrs = [
    `${name}=${value}`,
    "Path=/",
    "HttpOnly",
    // Lax: the OIDC callback is a top-level GET navigation from the IdP.
    "SameSite=Lax",
  ];
  if (options.maxAge !== undefined) attrs.push(`Max-Age=${options.maxAge}`);
  if (options.secure) attrs.push("Secure");
  return attrs.join("; ");
}

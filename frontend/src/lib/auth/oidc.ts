/**
 * Minimal OIDC Authorization Code + PKCE client built on jose.
 *
 * Supports confidential clients (client_secret_post). Discovery is cached
 * per process; JWKS is cached by jose itself.
 */

import {
  SignJWT,
  base64url,
  createRemoteJWKSet,
  jwtVerify,
} from "jose";

import type { AuthConfig } from "./config";
import type { Role } from "./rbac";
import { resolveRole } from "./rbac";

export interface DiscoveredEndpoints {
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  endSessionEndpoint?: string;
}

interface CacheEntry {
  endpoints: DiscoveredEndpoints;
  fetchedAt: number;
}

const DISCOVERY_TTL_MS = 10 * 60 * 1000;

let cache: CacheEntry | undefined;

export function resetDiscoveryCache(): void {
  cache = undefined;
}

export async function discover(config: AuthConfig): Promise<DiscoveredEndpoints> {
  if (cache && Date.now() - cache.fetchedAt < DISCOVERY_TTL_MS) {
    return cache.endpoints;
  }
  const url = `${config.oidc.issuer}/.well-known/openid-configuration`;
  const res = await fetch(url, {
    signal: AbortSignal.timeout(5_000),
    cache: "no-store",
  });
  if (!res.ok) {
    throw new OidcError(`discovery failed: issuer returned HTTP ${res.status}`);
  }
  const doc = (await res.json()) as Record<string, string | undefined>;
  const { authorization_endpoint: a, token_endpoint: t, jwks_uri: j } = doc;
  if (!a || !t || !j) {
    throw new OidcError("discovery document missing required endpoints");
  }
  const endpoints: DiscoveredEndpoints = {
    authorizationEndpoint: a,
    tokenEndpoint: t,
    jwksUri: j,
    endSessionEndpoint: doc.end_session_endpoint,
  };
  cache = { endpoints, fetchedAt: Date.now() };
  return endpoints;
}

export class OidcError extends Error {}

function randomB64url(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base64url.encode(buf);
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );
  return base64url.encode(new Uint8Array(digest));
}

/** Everything the login route needs to start the dance. */
export interface LoginRedirect {
  authorizeUrl: string;
  /** Compact JWS protecting state/nonce/verifier until the callback. */
  stateJwt: string;
}

export async function buildLoginRedirect(
  config: AuthConfig,
  redirectUri: string
): Promise<LoginRedirect> {
  const endpoints = await discover(config);
  const state = randomB64url();
  const nonce = randomB64url();
  const verifier = randomB64url(48);
  const challenge = await pkceChallenge(verifier);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.oidc.clientId,
    redirect_uri: redirectUri,
    scope: "openid email profile",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });

  // The transit cookie is itself a signed JWT so a tampered state cannot
  // be smuggled through the callback.
  const now = Math.floor(Date.now() / 1000);
  const stateJwt = await new SignJWT({
    state,
    nonce,
    verifier,
    return_to: "/",
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer("agentguard-console")
    .setAudience("agentguard-console")
    .setIssuedAt(now)
    .setExpirationTime(now + 600)
    .sign(config.sessionSecret);

  return {
    authorizeUrl: `${endpoints.authorizationEndpoint}?${params}`,
    stateJwt,
  };
}

export class LoginFailed extends Error {}

/** Result of a completed callback exchange. */
export interface CompletedLogin {
  sub: string;
  email?: string;
  name?: string;
  role: Role;
  idToken: string;
  endSessionEndpoint?: string;
}

export async function completeLogin(
  config: AuthConfig,
  searchParams: URLSearchParams,
  stateCookieValue: string | undefined,
  redirectUri: string
): Promise<CompletedLogin> {
  if (!stateCookieValue) throw new LoginFailed("missing OIDC state cookie");

  let stateClaims: Record<string, unknown>;
  try {
    ({ payload: stateClaims } = await jwtVerify(stateCookieValue, config.sessionSecret, {
      issuer: "agentguard-console",
      audience: "agentguard-console",
      algorithms: ["HS256"],
    }));
  } catch {
    throw new LoginFailed("invalid or expired OIDC state");
  }

  const code = searchParams.get("code");
  const state = searchParams.get("state");
  if (!code || !state || state !== stateClaims.state) {
    throw new LoginFailed("state mismatch");
  }

  const endpoints = await discover(config);
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: config.oidc.clientId,
    client_secret: config.oidc.clientSecret,
    code_verifier: String(stateClaims.verifier ?? ""),
  });
  const tokenRes = await fetch(endpoints.tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
    signal: AbortSignal.timeout(5_000),
    cache: "no-store",
  });
  if (!tokenRes.ok) {
    throw new LoginFailed(`token endpoint returned HTTP ${tokenRes.status}`);
  }
  const tokens = (await tokenRes.json()) as { id_token?: string };
  if (!tokens.id_token) throw new LoginFailed("token response missing id_token");

  const JWKS = createRemoteJWKSet(new URL(endpoints.jwksUri));
  let claims: Record<string, unknown>;
  try {
    ({ payload: claims } = await jwtVerify(tokens.id_token, JWKS, {
      issuer: config.oidc.issuer,
      audience: config.oidc.clientId,
    }));
  } catch {
    throw new LoginFailed("ID token validation failed");
  }
  if (claims.nonce !== stateClaims.nonce) {
    throw new LoginFailed("nonce mismatch");
  }
  const sub = claims.sub;
  if (typeof sub !== "string") throw new LoginFailed("ID token missing sub");

  return {
    sub,
    email: typeof claims.email === "string" ? claims.email : undefined,
    name: typeof claims.name === "string" ? claims.name : undefined,
    role: resolveRole(config, claims),
    idToken: tokens.id_token,
    endSessionEndpoint: endpoints.endSessionEndpoint,
  };
}

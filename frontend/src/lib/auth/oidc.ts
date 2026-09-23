/**
 * Minimal OIDC Authorization Code + PKCE client built on jose.
 *
 * Supports confidential clients (client_secret_post). Discovery is cached
 * per process; JWKS is cached by jose itself.
 */

import {
  customFetch,
  SignJWT,
  base64url,
  createRemoteJWKSet,
  jwtVerify,
} from "jose";
import { z } from "zod";
import { readBoundedJson } from "../bounded_json";

import type { AuthConfig } from "./config";
import type { Role } from "./rbac";
import { resolveRole } from "./rbac";
import { validateOidcEndpoint } from "./endpoint_url";

/** Required fields of an OIDC discovery document. */
const discoverySchema = z.object({
  authorization_endpoint: z.string(),
  token_endpoint: z.string(),
  jwks_uri: z.string(),
  end_session_endpoint: z.string().optional(),
});

/** Fields we rely on from the token endpoint response. */
const tokenResponseSchema = z.object({
  id_token: z.string(),
});

/** Endpoints needed for the authorization-code flow, from discovery. */
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
const MAX_DISCOVERY_CACHE_ENTRIES = 64;
const MAX_JWKS_CACHE_ENTRIES = 64;
const MAX_DISCOVERY_RESPONSE_BYTES = 64 * 1024;
const MAX_TOKEN_RESPONSE_BYTES = 256 * 1024;
const MAX_JWKS_RESPONSE_BYTES = 256 * 1024;

const discoveryCache = new Map<string, CacheEntry>();
const discoveryInFlight = new Map<string, Promise<DiscoveredEndpoints>>();
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

/** Test hook: drop the memoized discovery document. */
export function resetDiscoveryCache(): void {
  discoveryCache.clear();
  discoveryInFlight.clear();
  jwksCache.clear();
}

function remoteJwks(uri: string): ReturnType<typeof createRemoteJWKSet> {
  const cached = jwksCache.get(uri);
  if (cached) {
    jwksCache.delete(uri);
    jwksCache.set(uri, cached);
    return cached;
  }

  const resolver = createRemoteJWKSet(new URL(uri), {
    [customFetch]: async (url, options) => {
      const response = await fetch(url, {
        ...options,
        cache: "no-store",
        redirect: "error",
      });
      if (response.status !== 200) return response;
      const jwks = await readBoundedJson(response, MAX_JWKS_RESPONSE_BYTES, "OIDC JWKS");
      return Response.json(jwks);
    },
  });
  jwksCache.set(uri, resolver);
  if (jwksCache.size > MAX_JWKS_CACHE_ENTRIES) {
    const oldestUri = jwksCache.keys().next().value;
    if (oldestUri) jwksCache.delete(oldestUri);
  }
  return resolver;
}

/** Fetch (and cache) the issuer's OIDC discovery document. */
export async function discover(config: AuthConfig): Promise<DiscoveredEndpoints> {
  const issuer = config.oidc.issuer.replace(/\/+$/, "");
  const now = Date.now();
  const cached = discoveryCache.get(issuer);
  if (cached && now - cached.fetchedAt < DISCOVERY_TTL_MS) {
    // Maintain LRU order while keeping the TTL anchored to fetch time.
    discoveryCache.delete(issuer);
    discoveryCache.set(issuer, cached);
    return cached.endpoints;
  }
  if (cached) discoveryCache.delete(issuer);

  const inFlight = discoveryInFlight.get(issuer);
  if (inFlight) return inFlight;

  const request = (async () => {
    const url = `${issuer}/.well-known/openid-configuration`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(5_000),
      cache: "no-store",
      redirect: "error",
    });
    if (!res.ok) {
      throw new OidcError(`discovery failed: issuer returned HTTP ${res.status}`);
    }
    let document: unknown;
    try {
      document = await readBoundedJson(res, MAX_DISCOVERY_RESPONSE_BYTES, "OIDC discovery");
    } catch {
      throw new OidcError("discovery document is invalid or exceeds the size limit");
    }
    const parsed = discoverySchema.safeParse(document);
    if (!parsed.success) {
      throw new OidcError("discovery document missing required endpoints");
    }
    const doc = parsed.data;
    const endpoints: DiscoveredEndpoints = {
      authorizationEndpoint: doc.authorization_endpoint,
      tokenEndpoint: doc.token_endpoint,
      jwksUri: doc.jwks_uri,
      endSessionEndpoint: doc.end_session_endpoint,
    };
    for (const endpoint of [
      endpoints.authorizationEndpoint,
      endpoints.tokenEndpoint,
      endpoints.jwksUri,
      endpoints.endSessionEndpoint,
    ]) {
      if (!endpoint) continue;
      const issue = validateOidcEndpoint(endpoint);
      if (issue) throw new OidcError(`discovery endpoint ${issue}`);
    }

    discoveryCache.delete(issuer);
    discoveryCache.set(issuer, { endpoints, fetchedAt: Date.now() });
    if (discoveryCache.size > MAX_DISCOVERY_CACHE_ENTRIES) {
      const oldestIssuer = discoveryCache.keys().next().value;
      if (oldestIssuer) discoveryCache.delete(oldestIssuer);
    }
    return endpoints;
  })();
  discoveryInFlight.set(issuer, request);
  try {
    return await request;
  } finally {
    if (discoveryInFlight.get(issuer) === request) {
      discoveryInFlight.delete(issuer);
    }
  }
}

/** Error raised for OIDC protocol/discovery failures. */
export class OidcError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OidcError";
  }
}

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

/** Start the authorization-code flow: build the IdP redirect URL and state JWT. */
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

/** Error raised when a login attempt cannot be completed. */
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

/**
 * Complete the callback: validate state, exchange the code, verify the ID
 * token (issuer/audience/nonce) and resolve the console role.
 */
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
    redirect: "error",
  });
  if (!tokenRes.ok) {
    throw new LoginFailed(`token endpoint returned HTTP ${tokenRes.status}`);
  }
  let tokenDocument: unknown;
  try {
    tokenDocument = await readBoundedJson(tokenRes, MAX_TOKEN_RESPONSE_BYTES, "OIDC token");
  } catch {
    throw new LoginFailed("token endpoint returned an invalid response");
  }
  const parsedTokens = tokenResponseSchema.safeParse(tokenDocument);
  if (!parsedTokens.success) {
    throw new LoginFailed("token response missing id_token");
  }
  const tokens = parsedTokens.data;

  const JWKS = remoteJwks(endpoints.jwksUri);
  let claims: Record<string, unknown>;
  try {
    ({ payload: claims } = await jwtVerify(tokens.id_token, JWKS, {
      issuer: config.oidc.issuer,
      audience: config.oidc.clientId,
      requiredClaims: ["exp", "iat", "sub"],
      maxTokenAge: "10m",
      clockTolerance: 60,
    }));
  } catch {
    throw new LoginFailed("ID token validation failed");
  }
  const multipleAudiences = Array.isArray(claims.aud) && claims.aud.length > 1;
  if (
    (multipleAudiences && claims.azp !== config.oidc.clientId) ||
    (claims.azp !== undefined && claims.azp !== config.oidc.clientId)
  ) {
    throw new LoginFailed("ID token authorized party mismatch");
  }
  if (claims.nonce !== stateClaims.nonce) {
    throw new LoginFailed("nonce mismatch");
  }
  const sub = claims.sub;
  if (
    typeof sub !== "string" ||
    sub.length < 1 ||
    sub.length > 255 ||
    !/^[\x00-\x7F]+$/.test(sub)
  ) {
    throw new LoginFailed("ID token has an invalid sub claim");
  }

  return {
    sub,
    email: typeof claims.email === "string" ? claims.email : undefined,
    name: typeof claims.name === "string" ? claims.name : undefined,
    role: resolveRole(config, claims),
    idToken: tokens.id_token,
    endSessionEndpoint: endpoints.endSessionEndpoint,
  };
}

import { DEFAULT_SESSION_REDIS_PREFIX, RedisSessionStore } from "./session_store.ts";
import type { SessionStore } from "./session_store.ts";
import { SESSION_TTL_SECONDS } from "./session.ts";
import { isValidRedisKeyPrefix } from "../redis_key_prefix.ts";
import { validateSharedStoreUrl } from "../shared_store_url.ts";
import { validateOidcEndpoint, validatePdpEndpoint } from "./endpoint_url.ts";

/**
 * Console authentication configuration.
 *
 * Fail-closed: if any required variable is missing the console refuses to
 * serve protected content (login returns 503, proxy blocks all routes).
 * There is deliberately no "auth disabled" mode.
 */

/** OIDC relying-party settings for the console. */
export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
}

/** Fully resolved console authentication configuration. */
export interface AuthConfig {
  oidc: OidcConfig;
  /** Signing key for console-issued session/state JWTs. */
  sessionSecret: Uint8Array;
  /** Session maximum lifetime; roles are resolved from OIDC again at next login. */
  sessionTtlSeconds: number;
  /** Shared session state; memory is development-only. */
  sessionStore?: SessionStore;
  /** ID-token claim that carries admin group membership. */
  adminClaim: string;
  /** Claim values granting the admin role. Empty => nobody is admin. */
  adminValues: string[];
  /** agentguard PDP base URL (no trailing slash). */
  pdpUrl: string;
  /** Bearer token sent with PDP requests, if the PDP requires one. */
  pdpBearer?: string;
  /** Whether the configured reverse proxy is trusted to overwrite forwarded client/origin headers. */
  trustProxyHeaders: boolean;
  /** Allow cookies without Secure (local/e2e over plain HTTP only). */
  insecureCookie: boolean;
}

/** Either a valid config or the reason authentication cannot start. */
export type AuthConfigResult =
  | { valid: true; config: AuthConfig }
  | { valid: false; reason: string };

function readEnv(): AuthConfigResult {
  const missing: string[] = [];
  const need = (name: string): string => {
    const v = process.env[name];
    if (!v) missing.push(name);
    return v ?? "";
  };

  const issuer = stripSlash(need("AGENTGUARD_OIDC_ISSUER"));
  const clientId = need("AGENTGUARD_OIDC_CLIENT_ID");
  const clientSecret = need("AGENTGUARD_OIDC_CLIENT_SECRET");
  const secret = need("AGENTGUARD_SESSION_SECRET");
  const sessionTtlRaw = process.env.AGENTGUARD_SESSION_TTL_SECONDS;
  const sessionTtlSeconds = sessionTtlRaw === undefined
    ? SESSION_TTL_SECONDS
    : /^\d+$/.test(sessionTtlRaw) ? Number(sessionTtlRaw) : Number.NaN;
  const sessionStoreMode = process.env.AGENTGUARD_SESSION_STORE ||
    (process.env.NODE_ENV === "production" ? "redis" : "memory");
  const sessionRedisUrl = process.env.AGENTGUARD_SESSION_REDIS_URL;
  const sessionRedisToken = process.env.AGENTGUARD_SESSION_REDIS_TOKEN;
  const sessionRedisPrefix = process.env.AGENTGUARD_SESSION_REDIS_PREFIX || DEFAULT_SESSION_REDIS_PREFIX;
  const trustProxyHeaders = process.env.AGENTGUARD_TRUST_PROXY_HEADERS === "1";
  const configuredPdpUrl = process.env.AGENTGUARD_PDP_URL;
  const pdpUrl = stripSlash(configuredPdpUrl ?? "http://127.0.0.1:8443");
  const allowInsecurePdp = process.env.AGENTGUARD_PDP_ALLOW_INSECURE_INTERNAL === "1";

  if (missing.length > 0) {
    return {
      valid: false,
      reason:
        "console authentication is not configured; set " +
        `${missing.join(", ")} to enable it`,
    };
  }
  const issuerIssue = validateOidcEndpoint(issuer);
  if (issuerIssue) {
    return {
      valid: false,
      reason: `AGENTGUARD_OIDC_ISSUER ${issuerIssue}`,
    };
  }
  if (process.env.NODE_ENV === "production" && !configuredPdpUrl) {
    return { valid: false, reason: "AGENTGUARD_PDP_URL is required in production" };
  }
  const pdpIssue = validatePdpEndpoint(pdpUrl, process.env.NODE_ENV === "production", allowInsecurePdp);
  if (pdpIssue) {
    return { valid: false, reason: `AGENTGUARD_PDP_URL ${pdpIssue}` };
  }
  if (
    process.env.AGENTGUARD_PDP_ALLOW_INSECURE_INTERNAL !== undefined &&
    process.env.AGENTGUARD_PDP_ALLOW_INSECURE_INTERNAL !== "0" &&
    process.env.AGENTGUARD_PDP_ALLOW_INSECURE_INTERNAL !== "1"
  ) {
    return { valid: false, reason: "AGENTGUARD_PDP_ALLOW_INSECURE_INTERNAL must be 0 or 1" };
  }
  if (secret.length < 32) {
    return {
      valid: false,
      reason: "AGENTGUARD_SESSION_SECRET must be at least 32 characters",
    };
  }
  if (
    !Number.isSafeInteger(sessionTtlSeconds) ||
    sessionTtlSeconds < 300 ||
    sessionTtlSeconds > SESSION_TTL_SECONDS
  ) {
    return {
      valid: false,
      reason: `AGENTGUARD_SESSION_TTL_SECONDS must be an integer from 300 to ${SESSION_TTL_SECONDS}`,
    };
  }
  if (sessionStoreMode !== "memory" && sessionStoreMode !== "redis") {
    return { valid: false, reason: "AGENTGUARD_SESSION_STORE must be memory or redis" };
  }
  if (process.env.NODE_ENV === "production" && sessionStoreMode !== "redis") {
    return {
      valid: false,
      reason: "production console sessions require AGENTGUARD_SESSION_STORE=redis",
    };
  }
  if (sessionStoreMode === "redis" && (!sessionRedisUrl || !sessionRedisToken)) {
    return {
      valid: false,
      reason:
        "production console sessions require AGENTGUARD_SESSION_REDIS_URL and AGENTGUARD_SESSION_REDIS_TOKEN",
    };
  }
  if (sessionStoreMode === "redis" && !isValidRedisKeyPrefix(sessionRedisPrefix)) {
    return {
      valid: false,
      reason: "AGENTGUARD_SESSION_REDIS_PREFIX must contain 1-128 safe characters",
    };
  }
  if (sessionStoreMode === "redis" && sessionRedisUrl) {
    const issue = validateSharedStoreUrl(sessionRedisUrl);
    if (issue) {
      return {
        valid: false,
        reason: `AGENTGUARD_SESSION_REDIS_URL ${issue}`,
      };
    }
  }
  if (
    process.env.AGENTGUARD_TRUST_PROXY_HEADERS !== undefined &&
    process.env.AGENTGUARD_TRUST_PROXY_HEADERS !== "0" &&
    process.env.AGENTGUARD_TRUST_PROXY_HEADERS !== "1"
  ) {
    return {
      valid: false,
      reason: "AGENTGUARD_TRUST_PROXY_HEADERS must be 0 or 1",
    };
  }
  if (process.env.NODE_ENV === "production" && !trustProxyHeaders) {
    return {
      valid: false,
      reason:
        "production console requires AGENTGUARD_TRUST_PROXY_HEADERS=1 behind a proxy that overwrites X-Forwarded-For, X-Forwarded-Host, and X-Forwarded-Proto",
    };
  }
  if (process.env.NODE_ENV === "production" && !process.env.AGENTGUARD_PDP_BEARER) {
    return {
      valid: false,
      reason: "production console requires AGENTGUARD_PDP_BEARER for its authenticated PDP connection",
    };
  }

  const adminClaim = process.env.AGENTGUARD_ADMIN_CLAIM || "groups";
  const adminValues = (process.env.AGENTGUARD_ADMIN_VALUES ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  return {
    valid: true,
    config: {
      oidc: { issuer, clientId, clientSecret },
      sessionSecret: new TextEncoder().encode(secret),
      sessionTtlSeconds,
      // Next's edge proxy and Node route handlers do not share an in-memory
      // module instance. Development therefore keeps the signed-cookie
      // fallback; production is rejected above unless Redis is configured.
      sessionStore:
        sessionStoreMode === "redis"
          ? new RedisSessionStore(sessionRedisUrl!, sessionRedisToken!, fetch, sessionRedisPrefix)
          : undefined,
      adminClaim,
      adminValues,
      pdpUrl,
      pdpBearer: process.env.AGENTGUARD_PDP_BEARER,
      trustProxyHeaders,
      // Set only for local/e2e runs over plain HTTP.
      insecureCookie: process.env.AGENTGUARD_INSECURE_COOKIE === "1",
    },
  };
}

function stripSlash(s: string): string {
  return s.replace(/\/+$/, "");
}

/** Cached per process; env does not change at runtime. */
let cached: AuthConfigResult | undefined;

/** Read and memoize console auth configuration from the environment. */
export function authConfig(): AuthConfigResult {
  cached ??= readEnv();
  return cached;
}

/** Test hook: drop the memoized config. */
export function resetAuthConfigCache(): void {
  cached = undefined;
}

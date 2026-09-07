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
  /** ID-token claim that carries admin group membership. */
  adminClaim: string;
  /** Claim values granting the admin role. Empty => nobody is admin. */
  adminValues: string[];
  /** agentguard PDP base URL (no trailing slash). */
  pdpUrl: string;
  /** Bearer token sent with PDP requests, if the PDP requires one. */
  pdpBearer?: string;
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
  const pdpUrl = stripSlash(process.env.AGENTGUARD_PDP_URL ?? "http://127.0.0.1:8443");

  if (missing.length > 0) {
    return {
      valid: false,
      reason:
        "console authentication is not configured; set " +
        `${missing.join(", ")} to enable it`,
    };
  }
  if (secret.length < 32) {
    return {
      valid: false,
      reason: "AGENTGUARD_SESSION_SECRET must be at least 32 characters",
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
      adminClaim,
      adminValues,
      pdpUrl,
      pdpBearer: process.env.AGENTGUARD_PDP_BEARER,
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

import { isIP } from "node:net";

/** Validate a URL used by the OIDC client before sending credentials or tokens. */
export function validateOidcEndpoint(
  value: string,
  production = process.env.NODE_ENV === "production",
): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "must be an absolute URL";
  }

  if (url.username || url.password) return "must not include URL credentials";
  if (url.protocol === "https:") return undefined;

  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  const loopback = hostname === "localhost" || hostname === "::1" ||
    (isIP(hostname) === 4 && hostname.startsWith("127."));
  if (!production && url.protocol === "http:" && loopback) return undefined;

  return production
    ? "must use HTTPS in production"
    : "must use HTTPS, except for loopback HTTP in development";
}

/**
 * Validate the PDP URL before the console sends its privileged bearer token.
 * Production HTTP is permitted only when an operator explicitly accepts the
 * private-network trust boundary (for example, with service-mesh mTLS).
 */
export function validatePdpEndpoint(
  value: string,
  production = process.env.NODE_ENV === "production",
  allowInsecureInternal = process.env.AGENTGUARD_PDP_ALLOW_INSECURE_INTERNAL === "1",
): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "must be an absolute URL";
  }

  if (url.username || url.password) return "must not include URL credentials";
  if (url.protocol === "https:") return undefined;
  if (url.protocol !== "http:") return "must use HTTP or HTTPS";
  if (production && !allowInsecureInternal) {
    return "must use HTTPS in production unless AGENTGUARD_PDP_ALLOW_INSECURE_INTERNAL=1 explicitly accepts the internal-network trust boundary";
  }
  return undefined;
}

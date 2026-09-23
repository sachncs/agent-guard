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
  if (production && !isPrivatePdpHost(url.hostname)) {
    return "HTTP PDP URL must target loopback, a private IP, or cluster-local DNS";
  }
  return undefined;
}

function isPrivatePdpHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (host === "localhost" || host === "::1") return true;

  const ipVersion = isIP(host);
  if (ipVersion === 4) {
    const octets = host.split(".").map(Number);
    return octets[0] === 10 ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168) ||
      octets[0] === 127;
  }
  if (ipVersion === 6) return /^(fc|fd)/.test(host);

  // Kubernetes Services may be addressed by their namespace-qualified name
  // or the short service name used by the checked-in reference Deployment.
  return !host.includes(".") || host.endsWith(".svc");
}

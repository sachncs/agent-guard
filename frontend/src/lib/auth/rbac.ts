/**
 * Role mapping: any authenticated user is a viewer; admin requires the
 * configured ID-token claim to carry one of the configured values.
 */

import type { AuthConfig } from "./config";

export type Role = "viewer" | "admin";

export function resolveRole(
  config: Pick<AuthConfig, "adminClaim" | "adminValues">,
  idTokenClaims: Record<string, unknown>
): Role {
  const raw = idTokenClaims[config.adminClaim];
  const values = Array.isArray(raw)
    ? raw.filter((v): v is string => typeof v === "string")
    : typeof raw === "string"
      ? [raw]
      : [];
  return values.some((v) => config.adminValues.includes(v)) ? "admin" : "viewer";
}

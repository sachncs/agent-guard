import { randomUUID } from "node:crypto";
import { AgentguardError, CLIUnavailable } from "agentguard";

export type ApiErrorKind = "cli_unavailable" | "cli_error" | "invalid_request" | "unknown";

export interface ApiErrorBody {
  error: string;
  kind: ApiErrorKind;
  reference: string;
}

/** Return a stable, non-sensitive error to the caller and retain diagnostics server-side. */
export function toApiErrorResponse(error: unknown): Response {
  const reference = randomUUID();
  const mapped = mapError(error);

  // CLI stderr and arbitrary exception messages can contain paths, policy
  // fragments, or request data. Keep detail in server logs, never in JSON.
  logInternalError(reference, mapped.kind, error);

  const body: ApiErrorBody = {
    error: mapped.message,
    kind: mapped.kind,
    reference,
  };
  return Response.json(body, { status: mapped.status });
}

/** Map PDP failures to a safe service-unavailable response for the simulator. */
export function pdpUnavailableResponse(error: unknown): Response {
  const reference = randomUUID();
  logInternalError(reference, "pdp_unavailable", error);
  return Response.json(
    {
      error: "The authorization service is temporarily unavailable.",
      kind: "pdp_unavailable",
      reference,
    },
    { status: 503 }
  );
}

/** Return a safe response when OIDC discovery or issuer communication fails. */
export function identityProviderUnavailableResponse(error: unknown): Response {
  const reference = randomUUID();
  logInternalError(reference, "idp_error", error);
  return Response.json(
    {
      error: "The identity provider is temporarily unavailable. Try again shortly.",
      kind: "idp_error",
      reference,
    },
    { status: 502 }
  );
}

function logInternalError(reference: string, kind: string, error: unknown): void {
  console.error("AgentGuard API operation failed", { reference, kind, error });
}

function mapError(error: unknown): {
  kind: ApiErrorKind;
  status: number;
  message: string;
} {
  if (error instanceof CLIUnavailable) {
    return {
      kind: "cli_unavailable",
      status: 503,
      message: "AgentGuard is temporarily unavailable. Try again shortly.",
    };
  }
  if (error instanceof AgentguardError) {
    return {
      kind: "cli_error",
      status: 422,
      message: "AgentGuard could not complete this operation.",
    };
  }
  if (error instanceof SyntaxError) {
    return { kind: "invalid_request", status: 400, message: "The request is not valid JSON." };
  }
  return { kind: "unknown", status: 500, message: "An internal error occurred." };
}

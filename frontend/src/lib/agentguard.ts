import "server-only";

import { AgentguardError, CLIUnavailable, Client } from "agentguard";

export type ApiErrorKind =
  | "cli_unavailable"
  | "cli_error"
  | "invalid_request"
  | "unknown";

export interface ApiErrorBody {
  error: string;
  kind: ApiErrorKind;
}

let cached: Client | null = null;

export function agentguard(): Client {
  if (!cached) {
    cached = new Client({
      store: process.env.AGENTGUARD_STORE ?? ".agentguard",
      auditLog: process.env.AGENTGUARD_AUDIT ?? ".audit/decisions.jsonl",
      bearerToken: process.env.AGENTGUARD_BEARER,
    });
  }
  return cached;
}

export function toErrorResponse(e: unknown): Response {
  const body = toErrorBody(e);
  const status: Record<ApiErrorKind, number> = {
    cli_unavailable: 503,
    cli_error: 422,
    invalid_request: 400,
    unknown: 500,
  };
  return Response.json(body, { status: status[body.kind] });
}

function toErrorBody(e: unknown): ApiErrorBody {
  if (e instanceof CLIUnavailable) {
    return { error: e.message, kind: "cli_unavailable" };
  }
  if (e instanceof AgentguardError) {
    return { error: e.message, kind: "cli_error" };
  }
  if (e instanceof SyntaxError) {
    return { error: `invalid JSON: ${e.message}`, kind: "invalid_request" };
  }
  return {
    error: e instanceof Error ? e.message : String(e),
    kind: "unknown",
  };
}

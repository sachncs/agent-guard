import "server-only";

import { Client } from "agentguard";
import { toApiErrorResponse } from "@/lib/api_error";

let cached: Client | null = null;

/** Memoized SDK {@link Client} configured from AGENTGUARD_* environment variables. */
export function agentguard(): Client {
  if (!cached) {
    cached = new Client({
      store: process.env.AGENTGUARD_STORE ?? ".agentguard",
      auditLog: process.env.AGENTGUARD_AUDIT ?? ".audit/decisions.jsonl",
      bearerToken: process.env.AGENTGUARD_BEARER,
      delegationKeyFile: process.env.AGENTGUARD_DELEGATION_KEY_FILE,
    });
  }
  return cached;
}

/** Async CLI operations keep Next.js route handlers from blocking the event loop. */
export async function logTail(
  n: number,
  filter?: { principal?: string; action?: string }
): Promise<unknown[]> {
  return agentguard().logTailAsync(n, filter);
}

export async function createDelegation(
  from: string,
  to: string,
  actions: string[],
  resources: string[],
  ttlSeconds: number
): Promise<string> {
  return agentguard().delegateAsync(from, to, actions, resources, ttlSeconds);
}

/** Map a thrown error to the appropriate JSON status/body for API routes. */
export function toErrorResponse(e: unknown): Response {
  return toApiErrorResponse(e);
}

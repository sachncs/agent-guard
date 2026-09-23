import "server-only";

import { z } from "zod";
import { readBoundedJson } from "../bounded_json.ts";

/**
 * HTTP client for the agentguard AuthZEN PDP (`agentguard-server`).
 *
 * The console evaluates simulator requests here instead of spawning the
 * CLI per request; every decision is audited by the PDP itself.
 */

export interface AuthZenEntity {
  type: string;
  id: string;
}

export interface AuthZenRequest {
  subject: AuthZenEntity;
  action: AuthZenEntity;
  resource: AuthZenEntity;
  context?: Record<string, unknown>;
}

export interface AuthZenDecision {
  decision: boolean;
  reason?: string;
}

const MAX_PDP_RESPONSE_BYTES = 256 * 1024;

/** Required fields of an AuthZEN evaluation response. */
const decisionSchema = z.object({
  decision: z.boolean(),
  reason: z.string().optional(),
});

export class PdpUnavailable extends Error {}

export async function evaluate(
  pdpUrl: string,
  bearer: string | undefined,
  req: AuthZenRequest,
  fetchImpl: typeof fetch = fetch,
): Promise<AuthZenDecision> {
  let res: Response;
  try {
    res = await fetchImpl(`${pdpUrl}/access/v1/evaluation`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(bearer && { Authorization: `Bearer ${bearer}` }),
      },
      body: JSON.stringify(req),
      signal: AbortSignal.timeout(5_000),
      cache: "no-store",
      redirect: "error",
    });
  } catch (e) {
    throw new PdpUnavailable(
      `PDP unreachable: ${e instanceof Error ? e.message : String(e)}`
    );
  }
  if (!res.ok) {
    throw new PdpUnavailable(`PDP returned HTTP ${res.status}`);
  }
  let payload: unknown;
  try {
    payload = await readBoundedJson(res, MAX_PDP_RESPONSE_BYTES, "PDP");
  } catch (error) {
    throw new PdpUnavailable(error instanceof Error ? error.message : "PDP returned an invalid response");
  }
  const parsed = decisionSchema.safeParse(payload);
  if (!parsed.success) {
    throw new PdpUnavailable("PDP returned an invalid decision payload");
  }
  return parsed.data;
}

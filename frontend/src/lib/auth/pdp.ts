import "server-only";

/**
 * HTTP client for the agentguard AuthZEN PDP (`agentguard serve`).
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

export class PdpUnavailable extends Error {}

export async function evaluate(
  pdpUrl: string,
  bearer: string | undefined,
  req: AuthZenRequest
): Promise<AuthZenDecision> {
  let res: Response;
  try {
    res = await fetch(`${pdpUrl}/access/v1/evaluation`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(bearer && { Authorization: `Bearer ${bearer}` }),
      },
      body: JSON.stringify(req),
      signal: AbortSignal.timeout(5_000),
      cache: "no-store",
    });
  } catch (e) {
    throw new PdpUnavailable(
      `PDP unreachable: ${e instanceof Error ? e.message : String(e)}`
    );
  }
  if (!res.ok) {
    throw new PdpUnavailable(`PDP returned HTTP ${res.status}`);
  }
  return (await res.json()) as AuthZenDecision;
}

import "server-only";

import { z } from "zod";

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
  const declaredLength = res.headers.get("content-length");
  if (declaredLength && /^\d+$/.test(declaredLength) && Number(declaredLength) > MAX_PDP_RESPONSE_BYTES) {
    await res.body?.cancel().catch(() => undefined);
    throw new PdpUnavailable("PDP response exceeded the size limit");
  }

  let payload: unknown;
  try {
    payload = JSON.parse(await readBoundedBody(res));
  } catch (error) {
    if (error instanceof PdpUnavailable) throw error;
    throw new PdpUnavailable("PDP returned invalid JSON");
  }
  const parsed = decisionSchema.safeParse(payload);
  if (!parsed.success) {
    throw new PdpUnavailable("PDP returned an invalid decision payload");
  }
  return parsed.data;
}

async function readBoundedBody(response: Response): Promise<string> {
  if (!response.body) throw new PdpUnavailable("PDP returned an empty response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_PDP_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new PdpUnavailable("PDP response exceeded the size limit");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof PdpUnavailable) throw error;
    throw new PdpUnavailable("PDP response body could not be read");
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new PdpUnavailable("PDP returned invalid UTF-8");
  }
}

import type { LogRecord } from "@/lib/api-types";
import { agentguard, toErrorResponse } from "@/lib/agentguard";

export async function GET(request: Request) {
  const params = new URL(request.url).searchParams;
  const n = Math.min(Math.max(Number(params.get("n") ?? 50) || 50, 1), 500);
  const principal = params.get("principal") ?? undefined;
  const action = params.get("action") ?? undefined;

  try {
    const records = agentguard().logTail(n, { principal, action }) as LogRecord[];
    return Response.json({ records });
  } catch (e) {
    return toErrorResponse(e);
  }
}

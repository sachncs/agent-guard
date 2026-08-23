import type { LogRecord } from "@/lib/api-types";
import { agentguard, toErrorResponse } from "@/lib/agentguard";
import { logQuerySchema } from "@/lib/api-schemas";
import { authConfig } from "@/lib/auth/config";
import { isResponse, requireViewer } from "@/lib/auth/guard";

export const runtime = "nodejs";

/** Audit log tail. Authenticated viewers; CLI-backed (no HTTP surface). */
export async function GET(request: Request) {
  const cfg = authConfig();
  if (!cfg.valid) {
    return Response.json({ error: cfg.reason, kind: "not_configured" }, { status: 503 });
  }

  const session = await requireViewer(cfg.config.sessionSecret, request);
  if (isResponse(session)) return session;

  const params = new URL(request.url).searchParams;
  const parsed = logQuerySchema.safeParse({
    n: params.get("n") ?? undefined,
    principal: params.get("principal") ?? undefined,
    action: params.get("action") ?? undefined,
  });
  if (!parsed.success) {
    return Response.json(
      {
        error: parsed.error.issues[0]?.message ?? "invalid query",
        kind: "invalid_request",
      },
      { status: 400 }
    );
  }

  try {
    const records = agentguard().logTail(parsed.data.n, {
      principal: parsed.data.principal,
      action: parsed.data.action,
    }) as LogRecord[];
    return Response.json({ records });
  } catch (e) {
    return toErrorResponse(e);
  }
}

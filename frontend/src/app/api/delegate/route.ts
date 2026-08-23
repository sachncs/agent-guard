import { agentguard, toErrorResponse } from "@/lib/agentguard";
import { parseJsonBody, delegateSchema } from "@/lib/api-schemas";
import { authConfig } from "@/lib/auth/config";
import { isResponse, requireAdmin } from "@/lib/auth/guard";
import { clientKey, rateLimit } from "@/lib/ratelimit";

export const runtime = "nodejs";

/** Mints a delegation token. Admin-only; rate limited. */
export async function POST(request: Request) {
  const cfg = authConfig();
  if (!cfg.valid) {
    return Response.json({ error: cfg.reason, kind: "not_configured" }, { status: 503 });
  }

  const session = await requireAdmin(cfg.config.sessionSecret, request);
  if (isResponse(session)) return session;

  const rl = rateLimit(`delegate:${clientKey(request)}`, 10);
  if (!rl.allowed) {
    return Response.json(
      { error: "rate limit exceeded", kind: "rate_limited" },
      { status: 429 }
    );
  }

  const parsed = await parseJsonBody(request, delegateSchema);
  if (!parsed.ok) {
    return Response.json(
      { error: parsed.error, kind: "invalid_request" },
      { status: parsed.status }
    );
  }
  const body = parsed.data;

  try {
    const token = agentguard().delegate(
      body.from,
      body.to,
      body.actions,
      body.resources,
      body.ttlSeconds
    );
    return Response.json({ token });
  } catch (e) {
    return toErrorResponse(e);
  }
}

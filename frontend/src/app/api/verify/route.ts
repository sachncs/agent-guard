import { agentguard, toErrorResponse } from "@/lib/agentguard";
import { parseJsonBody, verifySchema } from "@/lib/api_schemas";
import { authConfig } from "@/lib/auth/config";
import { isResponse, requireAdmin } from "@/lib/auth/guard";
import { clientKey, rateLimit } from "@/lib/ratelimit";

export const runtime = "nodejs";

/** Verifies a delegation token against a key set. Admin-only; rate limited. */
export async function POST(request: Request) {
  const cfg = authConfig();
  if (!cfg.valid) {
    return Response.json({ error: cfg.reason, kind: "not_configured" }, { status: 503 });
  }

  const session = await requireAdmin(cfg.config.sessionSecret, request);
  if (isResponse(session)) return session;

  const rl = rateLimit(`verify:${clientKey(request)}`, 20);
  if (!rl.allowed) {
    return Response.json(
      { error: "rate limit exceeded", kind: "rate_limited" },
      { status: 429 }
    );
  }

  const parsed = await parseJsonBody(request, verifySchema);
  if (!parsed.ok) {
    return Response.json(
      { error: parsed.error, kind: "invalid_request" },
      { status: parsed.status }
    );
  }
  const body = parsed.data;

  try {
    const result = agentguard().verify(body.token, body.keysFile);
    return Response.json({ result });
  } catch (e) {
    return toErrorResponse(e);
  }
}

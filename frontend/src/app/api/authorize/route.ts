import type { DecisionDto } from "@/lib/api-types";
import { parseJsonBody, authorizeSchema } from "@/lib/api-schemas";
import { authConfig } from "@/lib/auth/config";
import { isResponse, requireViewer } from "@/lib/auth/guard";
import { evaluate } from "@/lib/auth/pdp";

export const runtime = "nodejs";

/**
 * Policy simulator. Evaluated over HTTP against the AuthZEN PDP; the PDP
 * audits the decision itself, so no CLI spawn happens here.
 */
export async function POST(request: Request) {
  const cfg = authConfig();
  if (!cfg.valid) {
    return Response.json({ error: cfg.reason, kind: "not_configured" }, { status: 503 });
  }

  const session = await requireViewer(cfg.config.sessionSecret, request);
  if (isResponse(session)) return session;

  const parsed = await parseJsonBody(request, authorizeSchema);
  if (!parsed.ok) {
    return Response.json(
      { error: parsed.error, kind: "invalid_request" },
      { status: parsed.status }
    );
  }
  const body = parsed.data;

  // The AuthZEN surface cannot express subagent parentage (EntityRef has
  // no parent field), so refuse rather than silently mis-simulate.
  if (body.principalType === "agent" && body.parentUid) {
    return Response.json(
      {
        error:
          "subagent simulation is not supported through the PDP API; omit parentUid",
        kind: "invalid_request",
      },
      { status: 400 }
    );
  }

  try {
    const result = await evaluate(cfg.config.pdpUrl, cfg.config.pdpBearer, {
      subject: {
        type: body.principalType === "agent" ? "Agent" : "User",
        id: body.uid,
      },
      action: {
        type: "Action",
        id: body.operation
          ? `ToolCall::${body.tool}::${body.operation}`
          : `ToolCall::${body.tool}`,
      },
      resource: { type: body.resourceType, id: body.resourceId },
      context: { args: body.args, session: body.session },
    });

    // Explicit record construction instead of a cast: AuthZenDecision is an
    // interface and therefore lacks an implicit index signature.
    const raw: Record<string, unknown> = {
      decision: result.decision,
      ...(result.reason !== undefined && { reason: result.reason }),
    };
    const decision: DecisionDto = {
      effect: result.decision ? "allow" : "deny",
      policies: [],
      reasons: result.reason ? [result.reason] : [],
      request: {},
      raw,
    };
    return Response.json(decision satisfies DecisionDto);
  } catch (e) {
    return Response.json(
      {
        error: e instanceof Error ? e.message : String(e),
        kind: "pdp_unavailable",
      },
      { status: 503 }
    );
  }
}

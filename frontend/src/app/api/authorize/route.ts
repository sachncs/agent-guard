import { Action, Principal } from "agentguard";
import type { AuthorizeRequestBody, DecisionDto } from "@/lib/api-types";
import { agentguard, toErrorResponse } from "@/lib/agentguard";

export async function POST(request: Request) {
  let body: AuthorizeRequestBody;
  try {
    body = (await request.json()) as AuthorizeRequestBody;
  } catch {
    return Response.json(
      { error: "request body must be JSON", kind: "invalid_request" },
      { status: 400 }
    );
  }

  if (!body.uid || !body.tool || !body.resourceType || !body.resourceId) {
    return Response.json(
      { error: "uid, tool, resourceType and resourceId are required", kind: "invalid_request" },
      { status: 400 }
    );
  }

  const principal =
    body.principalType === "agent" && body.parentUid
      ? Principal.subagent(body.uid, body.parentUid)
      : body.principalType === "agent"
        ? Principal.agent(body.uid)
        : Principal.user(body.uid);

  const action = body.operation
    ? Action.toolOp(body.tool, body.operation)
    : Action.tool(body.tool);

  try {
    const decision = agentguard().authorize(principal, action, {
      entity_type: body.resourceType,
      uid: body.resourceId,
    }, {
      args: body.args ?? {},
      session: body.session ?? {},
    });
    return Response.json(decision satisfies DecisionDto);
  } catch (e) {
    return toErrorResponse(e);
  }
}

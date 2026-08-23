import type { DelegateRequestBody } from "@/lib/api-types";
import { agentguard, toErrorResponse } from "@/lib/agentguard";

export async function POST(request: Request) {
  let body: DelegateRequestBody;
  try {
    body = (await request.json()) as DelegateRequestBody;
  } catch {
    return Response.json(
      { error: "request body must be JSON", kind: "invalid_request" },
      { status: 400 }
    );
  }

  if (!body.from || !body.to || !body.actions?.length || !body.resources?.length) {
    return Response.json(
      { error: "from, to, actions and resources are required", kind: "invalid_request" },
      { status: 400 }
    );
  }

  try {
    const token = agentguard().delegate(
      body.from,
      body.to,
      body.actions,
      body.resources,
      body.ttlSeconds > 0 ? body.ttlSeconds : 900
    );
    return Response.json({ token });
  } catch (e) {
    return toErrorResponse(e);
  }
}

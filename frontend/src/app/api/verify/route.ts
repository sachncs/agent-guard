import type { VerifyRequestBody } from "@/lib/api-types";
import { agentguard, toErrorResponse } from "@/lib/agentguard";

export async function POST(request: Request) {
  let body: VerifyRequestBody;
  try {
    body = (await request.json()) as VerifyRequestBody;
  } catch {
    return Response.json(
      { error: "request body must be JSON", kind: "invalid_request" },
      { status: 400 }
    );
  }

  if (!body.token || !body.keysFile) {
    return Response.json(
      { error: "token and keysFile are required", kind: "invalid_request" },
      { status: 400 }
    );
  }

  try {
    const result = agentguard().verify(body.token, body.keysFile);
    return Response.json({ result });
  } catch (e) {
    return toErrorResponse(e);
  }
}

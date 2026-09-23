export const runtime = "nodejs";

/** Process liveness only; this endpoint does not depend on external services. */
export function GET() {
  return Response.json({ status: "ok" });
}

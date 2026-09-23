import { authConfig } from "@/lib/auth/config";
import { checkRateLimitStore } from "@/lib/ratelimit";

export const runtime = "nodejs";

/** Readiness requires valid auth configuration and reachable shared stores. */
export async function GET() {
  const cfg = authConfig();
  if (!cfg.valid) return Response.json({ ready: false }, { status: 503 });

  try {
    await Promise.all([
      cfg.config.sessionStore?.healthCheck(),
      checkRateLimitStore(),
    ]);
    return Response.json({ ready: true });
  } catch {
    return Response.json({ ready: false }, { status: 503 });
  }
}

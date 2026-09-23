import { authConfig } from "@/lib/auth/config";
import { checkPdpReady } from "@/lib/auth/pdp_health";
import { checkRateLimitStore } from "@/lib/ratelimit";

export const runtime = "nodejs";

/** Readiness requires valid auth configuration and reachable required dependencies. */
export async function GET() {
  const cfg = authConfig();
  if (!cfg.valid) return Response.json({ ready: false }, { status: 503 });

  try {
    await Promise.all([
      cfg.config.sessionStore?.healthCheck(),
      checkRateLimitStore(),
      checkPdpReady(cfg.config.pdpUrl, cfg.config.pdpBearer),
    ]);
    return Response.json({ ready: true });
  } catch {
    return Response.json({ ready: false }, { status: 503 });
  }
}

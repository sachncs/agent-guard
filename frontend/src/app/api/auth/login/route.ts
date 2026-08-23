import { authConfig } from "@/lib/auth/config";
import {
  OIDC_STATE_COOKIE,
  serializeSetCookie,
} from "@/lib/auth/session";
import { buildLoginRedirect } from "@/lib/auth/oidc";
import { publicOrigin } from "@/lib/origin";
import { clientKey, rateLimit } from "@/lib/ratelimit";

export const runtime = "nodejs";

/** Starts the OIDC authorization-code + PKCE flow. */
export async function GET(request: Request) {
  const cfg = authConfig();
  if (!cfg.valid) {
    return Response.json({ error: cfg.reason, kind: "not_configured" }, { status: 503 });
  }

  const rl = rateLimit(`login:${clientKey(request)}`, 10);
  if (!rl.allowed) {
    return Response.json(
      { error: "too many login attempts, retry later", kind: "rate_limited" },
      { status: 429 }
    );
  }

  const origin = publicOrigin(request);
  let authorizeUrl: string;
  let stateJwt: string;
  try {
    ({ authorizeUrl, stateJwt } = await buildLoginRedirect(cfg.config, `${origin}/api/auth/callback`));
  } catch (e) {
    return Response.json(
      {
        error: `identity provider unreachable: ${e instanceof Error ? e.message : e}`,
        kind: "idp_error",
      },
      { status: 502 }
    );
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: authorizeUrl,
      "Cache-Control": "no-store",
      "Set-Cookie": serializeSetCookie(OIDC_STATE_COOKIE, stateJwt, {
        maxAge: 600,
        secure: !cfg.config.insecureCookie,
      }),
    },
  });
}

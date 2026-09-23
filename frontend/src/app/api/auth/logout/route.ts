import { authConfig } from "@/lib/auth/config";
import { SESSION_COOKIE, parseCookieHeader, revokeSession, serializeSetCookie } from "@/lib/auth/session";
import { isSameOriginRequest } from "@/lib/origin";

export const runtime = "nodejs";

/** Clears the console session; POST avoids state changes through cross-site links. */
export async function POST(request: Request) {
  const cfg = authConfig();
  if (!isSameOriginRequest(request, cfg.valid && cfg.config.trustProxyHeaders)) {
    return Response.json(
      { error: "same-origin request required", kind: "csrf_rejected" },
      { status: 403, headers: { "Cache-Control": "no-store" } },
    );
  }
  const insecure = cfg.valid ? cfg.config.insecureCookie : true;
  let revocationFailed = false;
  if (cfg.valid) {
    try {
      await revokeSession(
        cfg.config.sessionSecret,
        parseCookieHeader(request.headers.get("cookie"))[SESSION_COOKIE],
        cfg.config.sessionStore,
      );
    } catch {
      revocationFailed = true;
    }
  }

  return new Response(null, {
    status: 303,
    headers: {
      Location: revocationFailed ? "/login?error=session_revoke_failed" : "/login",
      "Cache-Control": "no-store",
      "Set-Cookie": serializeSetCookie(SESSION_COOKIE, "", {
        maxAge: 0,
        secure: !insecure,
      }),
    },
  });
}

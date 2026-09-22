import { authConfig } from "@/lib/auth/config";
import { SESSION_COOKIE, parseCookieHeader, revokeSession, serializeSetCookie } from "@/lib/auth/session";

export const runtime = "nodejs";

/** Clears the console session; redirects to /login. */
export async function GET(request: Request) {
  const cfg = authConfig();
  const insecure = cfg.valid ? cfg.config.insecureCookie : true;
  if (cfg.valid) {
    await revokeSession(
      cfg.config.sessionSecret,
      parseCookieHeader(request.headers.get("cookie"))[SESSION_COOKIE],
      cfg.config.sessionStore,
    );
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: "/login",
      "Cache-Control": "no-store",
      "Set-Cookie": serializeSetCookie(SESSION_COOKIE, "", {
        maxAge: 0,
        secure: !insecure,
      }),
    },
  });
}

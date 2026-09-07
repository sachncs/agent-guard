import { authConfig } from "@/lib/auth/config";
import { SESSION_COOKIE, serializeSetCookie } from "@/lib/auth/session";

export const runtime = "nodejs";

/** Clears the console session; redirects to /login. */
export async function GET() {
  const cfg = authConfig();
  const insecure = cfg.valid ? cfg.config.insecureCookie : true;

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

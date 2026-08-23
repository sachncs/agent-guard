import { authConfig } from "@/lib/auth/config";
import { LoginFailed, completeLogin } from "@/lib/auth/oidc";
import {
  OIDC_STATE_COOKIE,
  SESSION_COOKIE,
  parseCookieHeader,
  serializeSetCookie,
  signSession,
} from "@/lib/auth/session";
import { publicOrigin } from "@/lib/origin";

export const runtime = "nodejs";

/** Finishes the OIDC flow: exchange code, validate ID token, set session. */
export async function GET(request: Request) {
  const cfg = authConfig();
  if (!cfg.valid) {
    return Response.json({ error: cfg.reason, kind: "not_configured" }, { status: 503 });
  }

  const cookies = parseCookieHeader(request.headers.get("cookie"));
  const origin = publicOrigin(request);
  const url = new URL(request.url);

  if (url.searchParams.get("error")) {
    return redirectWithError(request, cfg.config.insecureCookie);
  }

  try {
    const login = await completeLogin(
      cfg.config,
      url.searchParams,
      cookies[OIDC_STATE_COOKIE],
      `${origin}/api/auth/callback`
    );

    const sessionJwt = await signSession(cfg.config.sessionSecret, {
      sub: login.sub,
      email: login.email,
      name: login.name,
      admin: login.role === "admin",
    });

    return new Response(null, {
      status: 302,
      headers: [
        ["Location", "/"],
        ["Cache-Control", "no-store"],
        [
          "Set-Cookie",
          serializeSetCookie(SESSION_COOKIE, sessionJwt, {
            maxAge: 8 * 60 * 60,
            secure: !cfg.config.insecureCookie,
          }),
        ],
        // Consume the state cookie.
        [
          "Set-Cookie",
          serializeSetCookie(OIDC_STATE_COOKIE, "", {
            maxAge: 0,
            secure: !cfg.config.insecureCookie,
          }),
        ],
      ],
    });
  } catch (e) {
    if (e instanceof LoginFailed) {
      console.error("login failed:", e.message);
    }
    return redirectWithError(request, cfg.config.insecureCookie);
  }
}

function redirectWithError(_request: Request, insecureCookie: boolean): Response {
  const loginUrl = new URL("/login", _request.url);
  loginUrl.searchParams.set("error", "auth_failed");
  return new Response(null, {
    status: 302,
    headers: [
      ["Location", loginUrl.toString()],
      ["Cache-Control", "no-store"],
      [
        "Set-Cookie",
        serializeSetCookie(OIDC_STATE_COOKIE, "", { maxAge: 0, secure: !insecureCookie }),
      ],
    ],
  });
}

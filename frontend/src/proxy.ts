import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import { authConfig } from "@/lib/auth/config";
import { SESSION_COOKIE, parseCookieHeader, serializeSetCookie, verifySession } from "@/lib/auth/session";
import { applySecurityHeaders } from "@/lib/security-headers";

/**
 * Authentication gate + security headers for every console route.
 *
 * Fail-closed: when OIDC/session configuration is invalid, everything is
 * answered with 503 (pages get an explanatory body). There is no open
 * mode.
 */

function isHttps(request: NextRequest): boolean {
  const proto = request.headers.get("x-forwarded-proto");
  return proto ? proto.split(",")[0].trim() === "https" : request.nextUrl.protocol === "https:";
}

export async function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  const https = isHttps(request);
  const isApi = pathname.startsWith("/api/");
  const isAuthFlow = pathname.startsWith("/api/auth/") || pathname === "/login";
  const isStatic =
    pathname.startsWith("/_next/") ||
    pathname === "/favicon.ico" ||
    pathname === "/robots.txt" ||
    pathname.startsWith("/icons/");

  // Static assets skip auth but still get headers.
  if (isStatic) {
    return applySecurityHeaders(NextResponse.next(), process.env.NODE_ENV === "production", https);
  }

  const cfg = authConfig();

  if (!cfg.valid) {
    if (isAuthFlow) {
      // The login page itself renders the configuration error.
      return applySecurityHeaders(NextResponse.next(), false, https);
    }
    if (isApi) {
      return applySecurityHeaders(
        Response.json({ error: cfg.reason, kind: "not_configured" }, { status: 503 }),
        false,
        https
      );
    }
    return applySecurityHeaders(
      new NextResponse(notConfiguredPage(cfg.reason), {
        status: 503,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      }),
      false,
      https
    );
  }

  // Auth flow routes are reachable unauthenticated (that is their job).
  if (isAuthFlow) {
    return applySecurityHeaders(NextResponse.next(), process.env.NODE_ENV === "production", https);
  }

  const cookies = parseCookieHeader(request.headers.get("cookie"));
  const session = await verifySession(cfg.config.sessionSecret, cookies[SESSION_COOKIE]);

  if (!session.ok) {
    if (isApi) {
      return applySecurityHeaders(
        Response.json({ error: "authentication required", kind: "unauthenticated" }, { status: 401 }),
        process.env.NODE_ENV === "production",
        https
      );
    }
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("from", pathname + search);
    const res = NextResponse.redirect(loginUrl);
    // Drop any stale/invalid cookie so it does not linger.
    res.headers.append(
      "Set-Cookie",
      serializeSetCookie(SESSION_COOKIE, "", { maxAge: 0, secure: !cfg.config.insecureCookie })
    );
    return applySecurityHeaders(res, process.env.NODE_ENV === "production", https);
  }

  return applySecurityHeaders(
    NextResponse.next(),
    process.env.NODE_ENV === "production",
    https
  );
}

export const config = {
  matcher: ["/((?!_next/static|_next/image).*)"],
};

function notConfiguredPage(reason: string): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>agentguard console</title></head>
<body style="font-family: ui-monospace, monospace; max-width: 40rem; margin: 4rem auto; padding: 0 1rem;">
<h1>agentguard_console</h1>
<p><strong>Console authentication is not configured.</strong></p>
<p>${reason}</p>
<p>See frontend/README.md for the environment variable contract.</p>
</body>
</html>`;
}

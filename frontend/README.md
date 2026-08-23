# agentguard console

Admin console for [agentguard](../README.md) — Cedar-powered authorization
for AI agents. Built with **Next.js 16**, **React 19**, **Tailwind CSS v4**
and **shadcn/ui**.

**Authentication is mandatory.** Without a configured OIDC identity provider
the console answers `503` on every route — there is no open mode.

## Pages

| Route | Access | What it does |
|---|---|---|
| `/login` | public | SSO sign-in (OIDC Authorization Code + PKCE) |
| `/` | any signed-in user | **Dashboard** — hash-chained audit log tail with principal/action filters, allow/deny stats, auto-refresh |
| `/simulator` | any signed-in user | **Policy Simulator** — evaluated live against the AuthZEN PDP over HTTP |
| `/delegation` | **admin only** | Issue scoped JWS delegation tokens and verify existing ones |

## Authentication & RBAC

- Sign-in uses any OIDC-compliant provider (Keycloak, Okta, Entra, Google…).
- Sessions are HS256 JWSs in an `HttpOnly` `SameSite=Lax` cookie (8 h TTL),
  signed with `AGENTGUARD_SESSION_SECRET`.
- Roles are resolved once at login from the ID token: any authenticated user
  is a *viewer*; users whose configured admin claim carries one of the
  configured values get *admin* (delegation mint/verify). If no admin values
  are configured nobody is admin — fail closed.
- A proxy (`src/proxy.ts`, the Next 16 middleware convention) gates every
  route, strips stale cookies and applies security headers (CSP,
  `X-Frame-Options: DENY`, nosniff, referrer policy; HSTS over https).
- Mutating routes validate bodies with strict zod schemas (identifiers may
  not look like CLI flags) and rate-limit per client IP.

## Prerequisites

1. The `agentguard` CLI on your `PATH` (`~/.cargo/bin/agentguard` is
   auto-detected) — used by the audit-tail and delegation routes:

   ```bash
   cargo install --path crates/agentguard-cli
   ```

2. An initialized store at the repo root:

   ```bash
   agentguard init --name acme
   ```

3. An OIDC provider the console can reach for discovery + token exchange.
   For local testing without one, run `node scripts/e2e.mjs` which boots a
   mock IdP/PDP and drives the whole flow end-to-end.

## Run

From the repository root:

```bash
pnpm install
pnpm --filter frontend dev
```

Open <http://localhost:3000> and you will be redirected to `/login`.

## Configuration

Console fails to start serving unless the first four variables are set.

| Env var | Default | Purpose |
|---|---|---|
| `AGENTGUARD_OIDC_ISSUER` | *(required)* | IdP issuer URL, e.g. `https://idp.example.com/realms/acme` |
| `AGENTGUARD_OIDC_CLIENT_ID` | *(required)* | Confidential OIDC client id |
| `AGENTGUARD_OIDC_CLIENT_SECRET` | *(required)* | Client secret (`client_secret_post`) |
| `AGENTGUARD_SESSION_SECRET` | *(required)* | ≥32 chars; signs session/state cookies |
| `AGENTGUARD_ADMIN_CLAIM` | `groups` | ID-token claim checked for admin membership |
| `AGENTGUARD_ADMIN_VALUES` | *(empty ⇒ no admins)* | Comma-separated claim values granting admin |
| `AGENTGUARD_PDP_URL` | `http://127.0.0.1:8443` | AuthZEN PDP base URL (`agentguard serve`) |
| `AGENTGUARD_PDP_BEARER` | *(unset)* | Bearer token when the PDP requires auth |
| `AGENTGUARD_STORE` | `.agentguard` | Cedar schema + policies (CLI-backed routes) |
| `AGENTGUARD_AUDIT` | `.audit/decisions.jsonl` | Audit log destination (CLI-backed routes) |
| `AGENTGUARD_INSECURE_COOKIE` | *(unset)* | Set to `1` only for plain-HTTP local/e2e runs |

## Tests

```bash
pnpm --filter frontend test                      # unit tests (node:test)
pnpm --filter frontend exec node scripts/e2e.mjs # full auth flow vs prod build
```

The e2e script asserts the complete security posture: redirects, 401s, the
OIDC round trip (PKCE + nonce), viewer/admin RBAC, PDP-backed simulator
decisions, validation errors, rate limiting, logout, and the 503 fail-closed
mode.

## Honest limitations

- **Single node**: the rate limiter and session state are in-memory; run one
  replica behind a reverse proxy or swap in a shared store before scaling.
- **Per-request CLI spawns** for log/delegate/verify (no HTTP surface exists
  server-side yet); the simulator already avoids this via the PDP API.
- **TLS termination** is expected at your reverse proxy; set
  `X-Forwarded-Proto` so HSTS and secure cookies engage.
- CSP allows `'unsafe-inline'` scripts because the App Router hydration
  bootstrap requires it.

## Style guide compliance

Source follows the [Google TypeScript Style Guide][tsguide]. Deliberate,
framework-mandated deviations:

- **Default exports** for `page.tsx`/`layout.tsx` and `next.config.ts` — the
  Next.js App Router requires them.
- **Framework-fixed filenames** (`page.tsx`, `route.ts`, `layout.tsx`,
  `proxy.ts`) override the snake_case file rule.
- **`components/ui/`** is vendor-generated (shadcn/radix) and exempt;
  regenerating components would reintroduce upstream style.

[tsguide]: https://google.github.io/styleguide/tsguide.html

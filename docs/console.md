# Console deployment

The AgentGuard console is a separate Next.js application for security and
platform teams. It is not an authorization engine: the simulator calls the
PDP, audit/delegation routes call the local CLI, and every action still depends
on the PDP and policy store being configured correctly.

## Local development

From a clean checkout:

```bash
./scripts/setup.sh
cargo install --path crates/agentguard-cli
cp frontend/.env.example frontend/.env.local
pnpm --filter frontend dev
```

Authentication is fail-closed. Without all required OIDC and session settings,
the console returns `503` rather than exposing an open mode. The mock end-to-end
test supplies an isolated IdP and PDP for local verification:

```bash
pnpm --filter frontend exec node scripts/e2e.mjs
```

## Production configuration

Set these values through a secret manager or Kubernetes Secret:

| Variable | Requirement |
| --- | --- |
| `AGENTGUARD_OIDC_ISSUER` | OIDC issuer reachable by the console |
| `AGENTGUARD_OIDC_CLIENT_ID` | Confidential client registered with the issuer |
| `AGENTGUARD_OIDC_CLIENT_SECRET` | Never commit or bake into the image |
| `AGENTGUARD_SESSION_SECRET` | At least 32 random characters; rotate deliberately |
| `AGENTGUARD_SESSION_STORE` | `redis` in production; `memory` only for development |
| `AGENTGUARD_SESSION_REDIS_URL` / `AGENTGUARD_SESSION_REDIS_TOKEN` | Required for production session state |
| `AGENTGUARD_ADMIN_CLAIM` / `AGENTGUARD_ADMIN_VALUES` | Explicit admin mapping; empty values grant viewer only |
| `AGENTGUARD_PDP_URL` / `AGENTGUARD_PDP_BEARER` | Private PDP URL and optional bearer credential |
| `AGENTGUARD_DELEGATION_KEY_FILE` | Persistent Ed25519 private key for admin token issuance |
| `AGENTGUARD_RATE_LIMIT_REDIS_URL` / `AGENTGUARD_RATE_LIMIT_REDIS_TOKEN` | Required before running multiple replicas |
| `AGENTGUARD_INSECURE_COOKIE` | Local HTTP only; never set in production |

Terminate TLS before the console and preserve `X-Forwarded-Proto`. The
console uses secure cookies when the request is HTTPS and sends restrictive
security headers. The production image includes the pinned `agentguard` CLI;
mount the policy directory and audit file read-only, as the Kubernetes
reference does, and keep both paths private to the console runtime.

## Roles and failure behavior

Every authenticated user is a viewer. Only explicitly configured admin claim
values can issue or verify delegation tokens. Expired or invalid sessions are
cleared and redirected to login. Missing OIDC configuration, unavailable PDP
responses, CLI failures, malformed upstream payloads, and audit failures are
surfaced as errors; they never become an allow decision.

Use Redis-compatible shared sessions and rate limiting for horizontally scaled
console replicas. The in-memory stores are development-only and intentionally
do not provide cross-replica protection. Store session signing keys and Redis
credentials in the deployment secret manager.

## Release checks

Run lint, typecheck, unit tests, a production build, and the end-to-end flow.
Manually verify keyboard navigation, focus visibility, reduced motion, dark
mode, mobile tables, viewer/admin boundaries, expired sessions, PDP failure,
and rate-limit behavior before promotion.

# Console deployment

The AgentGuard console is a separate Next.js application for security and
platform teams. It is not an authorization engine: the simulator calls the
PDP, audit/delegation routes call the local CLI, and every action still depends
on the PDP and policy store being configured correctly.

The simulator maps its `args` fields to top-level Cedar context attributes
and sends `session` separately. The session object is authoritative if an
argument is also named `session`; this keeps tool arguments from replacing
session facts while matching the starter Cedar schema.

## Local development

From a clean checkout:

```bash
./scripts/setup.sh
cargo install --path crates/agentguard-cli
cp frontend/.env.example frontend/.env.local
pnpm --filter frontend dev
```

Authentication is fail-closed. Without all required OIDC and session settings,
the console returns `503` rather than exposing an open mode. The end-to-end
test supplies an isolated IdP, mock PDP, and Redis-compatible REST store, then runs
the production build through the full sign-in and simulator flow:

```bash
pnpm --filter frontend exec node scripts/e2e.mjs
```

For integration against the actual Rust PDP, install `protoc`, build the server,
then run the same production-console test with `AGENTGUARD_E2E_REAL_PDP=1`. This
mode loads an isolated Cedar schema and policy, checks real allow/deny decisions
and chained audit persistence, then stops and restarts the PDP to verify
fail-closed authorization and readiness recovery:

```bash
cargo build -p agentguard-server
AGENTGUARD_E2E_REAL_PDP=1 pnpm --filter frontend exec node scripts/e2e.mjs
```

## Production configuration

Set these values through a secret manager or Kubernetes Secret:

| Variable | Requirement |
| --- | --- |
| `AGENTGUARD_OIDC_ISSUER` | HTTPS OIDC issuer reachable by the console; issuer and discovered authorization, token, and JWKS endpoints must use HTTPS in production |
| `AGENTGUARD_OIDC_CLIENT_ID` | Confidential client registered with the issuer |
| `AGENTGUARD_OIDC_CLIENT_SECRET` | Never commit or bake into the image |
| `AGENTGUARD_SESSION_SECRET` | At least 32 random characters; rotate deliberately |
| `AGENTGUARD_SESSION_STORE` | `redis` in production; `memory` only for development |
| `AGENTGUARD_SESSION_REDIS_URL` / `AGENTGUARD_SESSION_REDIS_TOKEN` | Required for production session state; endpoint must use HTTPS and credentials must be supplied separately |
| `AGENTGUARD_ADMIN_CLAIM` / `AGENTGUARD_ADMIN_VALUES` | Explicit admin mapping; empty values grant viewer only |
| `AGENTGUARD_PDP_URL` / `AGENTGUARD_PDP_BEARER` | PDP URL and bearer credential; required in production, HTTPS required unless the internal transport exception is enabled |
| `AGENTGUARD_PDP_ALLOW_INSECURE_INTERNAL` | `0` by default; set to `1` only when the PDP HTTP hop is protected by a private cluster boundary or service-mesh mTLS; HTTP destinations are restricted to loopback, private IPv4/IPv6 IPs, or cluster-local DNS names |
| `AGENTGUARD_DELEGATION_KEY_FILE` | Persistent Ed25519 private key for admin token issuance |
| `AGENTGUARD_RATE_LIMIT_STORE` | `redis` in production; `memory` only for development/e2e |
| `AGENTGUARD_RATE_LIMIT_REDIS_URL` / `AGENTGUARD_RATE_LIMIT_REDIS_TOKEN` | Required for production rate limiting; endpoint must use HTTPS and credentials must be supplied separately |
| `AGENTGUARD_RATE_LIMIT_REDIS_PREFIX` | Optional key namespace, default `agentguard:ratelimit:`; configure a distinct prefix for each environment sharing one Redis database |
| `AGENTGUARD_TRUST_PROXY_HEADERS` | `1` in production, only behind the trusted reverse proxy |
| `AGENTGUARD_INSECURE_COOKIE` | Local HTTP only; never set in production |

Terminate TLS before the console and preserve `X-Forwarded-Proto`. In
production, set `AGENTGUARD_TRUST_PROXY_HEADERS=1` only if the proxy removes
client-supplied `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto`
and replaces them with one validated client address, the public host, and the
external scheme. The console uses those values for per-client rate limiting
and same-origin CSRF checks;
otherwise all users behind one ingress share a bucket. The console uses secure
cookies when the request is HTTPS and sends restrictive security headers. The
console-to-PDP credential is server-only. Use an identity-bound `authorize:any`
service key when the simulator must evaluate selected subjects; ordinary
`authorize` keys cannot act as another identity. Restrict console users through
OIDC/RBAC and never expose this credential to browser code. See the
[identity guide](identity.md) for the privilege boundary. The
production image includes the pinned `agentguard` CLI;
mount the policy directory and audit file read-only, as the Kubernetes
reference does, and keep both paths private to the console runtime.

## Health probes and failure behavior

The Kubernetes readiness probe uses `/api/health/ready`: it requires valid
console auth configuration, successful bounded `PING` checks to both shared
Redis-compatible stores, and a successful bounded `GET /readyz` from the
configured PDP. A dependency outage therefore removes the pod from service.
Liveness and startup use `/api/health/live`, which only reports whether the
process can serve HTTP; external outages do not trigger restart loops.

## Roles

Every authenticated user is a viewer. Only explicitly configured admin claim
values can issue or verify delegation tokens. Expired or invalid sessions are
cleared and redirected to login. Missing OIDC configuration, unavailable PDP
responses, CLI failures, malformed upstream payloads, and audit failures are
surfaced as errors; they never become an allow decision.

Use Redis-compatible shared sessions and rate limiting for horizontally scaled
console replicas. Login, delegation, verification, and simulator requests are
limited per trusted client; the simulator allows 60 evaluations per minute to
bound PDP and audit load. The in-memory stores are development-only and intentionally
do not provide cross-replica protection. Store session signing keys and Redis
credentials in the deployment secret manager.

## Release checks

Run lint, typecheck, unit tests, a production build, and the end-to-end flow.
Manually verify keyboard navigation, focus visibility, reduced motion, dark
mode, mobile tables, viewer/admin boundaries, expired sessions, PDP failure,
and rate-limit behavior before promotion.

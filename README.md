<p align="center">
  <img src="site/public/agentguard-wordmark.svg" alt="AgentGuard" width="360">
  <h1 align="center">AgentGuard</h1>
  <p align="center">Cedar-powered authorization for AI agents — per-tool-call decisions, tamper-evident audit, scoped delegation.</p>
  <p align="center">
    <a href="#installation"><img src="https://img.shields.io/badge/rust-1.89%2B-orange" alt="Rust"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
    <a href="https://github.com/sachncs/agent-guard/actions"><img src="https://img.shields.io/github/actions/workflow/status/sachncs/agent-guard/ci.yml?branch=master" alt="CI"></a>
    <a href="https://github.com/sachncs/agent-guard/stargazers"><img src="https://img.shields.io/github/stars/sachncs/agent-guard" alt="Stars"></a>
  </p>
</p>

**AgentGuard wraps [Cedar](https://www.cedarpolicy.com) and puts a verifiable authorization boundary between agent intent and tool execution.**

Every tool call is an explicit authorization decision. Every decision can be
recorded in a tamper-evident audit chain and bound to a short-lived identity.
The standalone HTTP PDP follows the [OpenID AuthZEN](https://openid.github.io/authzen/)
evaluation request model; the embedded engine and CLI remain separate local
integration surfaces.

## How It Works

```text
tool call ──► intercept (SDK / HTTP PDP) ──► evaluate Cedar policies ──► Allow │ Deny
                                                │
                                     every decision recorded
                                                ▼
                        hash-chained audit log (CEF / LEEF / ECS / JSONL export)
```

Each request carries a principal (`User::"alice"` or `Agent::"research"`), an action (`ToolCall::send_email`), a resource (`Mailbox::"alice@acme"`), and context (`session`, tool `args`). Cedar policies stored recursively under `.agentguard/policies/` are evaluated against the schema plus per-request entities — allow runs the tool, deny raises `AuthorizationDenied` back to the model.

## Features

- **Per-call authorization** — does this user/agent have permission to call this tool on this resource, right now, with this context?
- **Tamper-evident audit trail** — hash-chained decision log, exportable to your SIEM in CEF/LEEF/ECS/JSONL
- **Delegation primitives** — signed, expiring grants carry action/resource scope; the consuming tool adapter must verify the grant and enforce that scope. DPoP validation is a library capability, not automatically bound to delegation tokens.
- **Schema-validated policies** — security teams write Cedar, not imperative code; validated at authoring time
- **Composable identity primitives** — API-key authentication in the standalone PDP plus library JWT, OIDC, DPoP, and SPIFFE validators; RFC 8725 BCP crypto and RFC 8693-style delegation without proprietary protocols
- **Observable decisions** — Prometheus metrics, trace correlation, and pluggable telemetry sinks
- **Policy operations** — validate, diff, replay, analyze blast radius, and atomically reload standalone server snapshots
- **AuthZEN-compatible HTTP PDP** — use the documented evaluation endpoints with AuthZEN-aware clients; the repository-defined gRPC mirror is a separate plaintext transport
- **Local-first** — files in `.agentguard/` are the source of truth; `git diff` your policies; run in-process or as a sidecar
- **Admin console** — Next.js dashboard with OIDC sign-in, policy simulator, delegation management, audit browser

## Components

| Component | Purpose |
| --------- | ------- |
| `agentguard-core` (Rust) | Type-safe wrappers, decision cache, hash-chained audit log, TTL primitives |
| `agentguard` CLI | `init`, `validate`, `authorize`, `sim`, `api-key`, `delegate`, `verify`, `audit`, `schema`, `log`, `gen`, `doctor` |
| `agentguard-telemetry` (Rust) | Pluggable `Sink` trait, OTel/OTLP, Prometheus metrics |
| `agentguard-auth` (Rust) | Library validators for JWT (RFC 7519 + RFC 8725), OIDC (RFC 8414), API keys, DPoP (RFC 9449), SPIFFE/SPIRE, and jti replay protection; not standalone PDP auth modes |
| `agentguard-redis-store` (Rust) | Redis-compatible HTTPS REST adapter for shared delegation revocation state |
| `agentguard-policy` (Rust) | Versioned bundles, policy change notifications, diff, blast radius, dry-run |
| `agentguard-server` (Rust) | Standalone AuthZEN HTTP PDP, sidecar mode |
| `agentguard` (TypeScript SDK) | In-process Node.js bindings via the CLI |
| `frontend` (Next.js 16 console) | Dashboard, policy simulator, delegation console (shadcn/ui) |

See [CHANGELOG.md](CHANGELOG.md) for the change list. The canonical user journey is the [documentation site](https://sachncs.github.io/agent-guard/); the versioned repository guide index is [`docs/README.md`](docs/README.md).

## Surfaces

All four integration surfaces use the same Cedar request model. Audit records
are written by the configured server or CLI surface; embedded library callers
own audit wiring and do not share a physical log automatically:

| Surface | Integration | Best for |
| ------- | ----------- | -------- |
| TypeScript SDK | Spawns the CLI in-process | Node.js agents (Strands, LangChain, custom loops) |
| HTTP PDP | AuthZEN `POST /access/v1/evaluation` | Any language, gateways, sidecar deployments |
| CLI | Subprocess invocation | Scripts, CI checks, local evaluation |
| Admin console | Web UI over both | Security/ops teams simulating and delegating |

## Installation

### CLI (Rust)

```bash
# agentguard-server vendors protoc for its generated gRPC stubs. The optional
# SPIFFE feature and protobuf descriptor checks need a system protoc; set
# PROTOC to its executable path if it is not on PATH.
cargo install --path crates/agentguard-cli
```

### TypeScript SDK

```bash
pnpm install && pnpm --filter agentguard build
```

### Admin console

```bash
cd frontend
pnpm install
pnpm dev
```

**Requirements:** Rust 1.89+, Node.js ≥ 22.12 for the full repository setup (the standalone TypeScript SDK supports Node.js ≥ 20.9), and pnpm 11.22.x.

For a pinned clean-checkout setup, run `./scripts/setup.sh`; it also installs
the separate documentation-site workspace. Console configuration starts from
[`frontend/.env.example`](frontend/.env.example).

## Quick Start

### Initialize a project

```bash
mkdir my-agent && cd my-agent
agentguard init --name acme
```

This creates:

```text
.agentguard/
├── schema.cedarschema       # entity types, actions, context shapes
└── policies/
    ├── 10_admin.cedar       # admin override
    └── 20_agents.cedar      # agents can call declared ToolCalls
```

Edit the schema, write policies, validate:

```bash
agentguard validate
```

### Authorize a single request

```bash
agentguard authorize request.json
# ✗  DENY alice send_email alice@acme
```

Or with full audit output:

```bash
agentguard --output json authorize request.json | jq
```

### Start the server (sidecar mode)

```bash
agentguard-server \
    --listen 'tls://0.0.0.0:8443?cert=./server.pem&key=./server.key' \
    --store ./.agentguard \
    --audit .audit/decisions.jsonl \
    --auth apikey --auth-key-file ./keys.json
```

Server is now speaking [AuthZEN](https://openid.github.io/authzen/):

```bash
curl -X POST https://localhost:8443/access/v1/evaluation \
    -H "Content-Type: application/json" \
    -d '{
      "subject":  {"type": "User", "id": "alice"},
      "action":   {"type": "Action", "id": "ToolCall::send_email"},
      "resource": {"type": "Mailbox", "id": "alice@acme"},
      "context":  {"args": {"to": "bob@acme.dev"}, "session": {"ip": "10.0.0.1", "mfa": true}}
    }'
# {"decision": true, ...}
```

### TypeScript SDK

```typescript
import { Client, Principal, Action } from "agentguard";

const client = new Client({ store: ".agentguard" });

const decision = client.check(
  Principal.user("alice"),
  Action.tool("send_email"),
  { entity_type: "Mailbox", uid: "alice@acme" },
  { args: { to: "bob@acme.dev" }, session: { ip: "10.0.0.1", mfa: true } },
);
// raises AuthorizationDenied on deny; StepUpRequired when step-up is demanded

// Mint an RFC 8693-style, JWS-signed, time-boxed delegation grant:
client.delegate(
  'Agent::"research"',
  'Agent::"summarizer"',
  ["ToolCall::send_email"],
  ["Mailbox::*"],
  300,
);
```

The SDK runs the local CLI; it is not a remote PDP client. The synchronous
`check` shown above is suitable for scripts. In Node.js request handlers use
`await client.checkAsync(...)` or `authorizeAsync(...)` so CLI work does not
block the event loop. Async calls have per-client concurrency, timeout, and
output bounds.

Minting or signature verification alone does **not** authorize a tool call.
The Rust library's `VerifiedDelegation::allows` provides a fail-closed
subject/action/resource/constraint scope check, but the standalone PDP does not
consume delegation tokens. The integration at the tool boundary must bind the
trusted actor, authorize the original parent grant, evaluate Cedar policy, and
check revocation before each authorization. `DelegationRevocationStore` is an
async storage port; deployments must configure a durable shared adapter. The
`agentguard-redis-store` crate supplies a Redis-compatible HTTPS REST adapter.
The standalone PDP still does not consume delegation tokens or expose a
revocation endpoint.
`DelegationSigner::mint_attenuated` uses the verified parent's signing key and
constrains child grants to its actions, resources, constraints, and remaining
lifetime. See
[identity and delegation](docs/identity.md) for the enforcement contract.

### Verify and audit

```bash
# Walk the chain, verify every HMAC.
agentguard audit verify --audit .audit/decisions.jsonl --secret-file .chain-secret

# Export to ECS for Splunk/Elasticsearch.
agentguard audit export --format ecs --audit .audit/decisions.jsonl

# Diagnose a deployment.
agentguard doctor
# ✓ schema loads
# ✓ policies parse
# ✓ schema validation passes
# ✓ audit log writable
# ✓ hash chain verifies
```

## Configuration

| Setting | Flag / Env | Default | Description |
| ------- | ---------- | ------- | ----------- |
| Audit log path | `--audit` | `./.audit/decisions.jsonl` | Hash-chained audit log destination |
| Chain secret | `--secret-file` | `./.chain-secret` | HMAC key for the audit chain |
| Listen address | `--listen` | `tcp://127.0.0.1:8443` | Server listen address |
| Store path | `--store` | `./.agentguard` | Cedar schema and policy directory |
| gRPC listen | `--grpc-listen` / `AGENTGUARD_GRPC_LISTEN` | *(unset)* | Optional repository-defined plaintext `AccessEvaluation` mirror; not standardized AuthZEN gRPC |
| Auth mode | `AGENTGUARD_AUTH` | `disabled` | `apikey:<path>` enables bearer-token auth on `/access/v1/*` |
| Allow loopback bypass | `AGENTGUARD_ALLOW_LOOPBACK_BYPASS` | `0` | Set `1` to allow auth-disabled on a public bind |
| Decision cache TTL | `AGENTGUARD_CACHE_TTL` | `60s` | TTL for in-memory decision cache (humantime) |
| Decision cache capacity | `AGENTGUARD_CACHE_CAPACITY` | `10000` | Max entries in the decision cache |
| Deny cache TTL | `AGENTGUARD_DENY_CACHE_TTL` | `5s` | TTL for deny entries in the decision cache (humantime) |
| Audit rotation threshold | `AGENTGUARD_AUDIT_MAX_BYTES` | *(unset)* | Rotate the audit log when the active file exceeds this size |
| JWKS refresh | `AGENTGUARD_JWKS_REFRESH` | `30s` | Cached JWKS refresh interval (humantime) |
| OTLP endpoint | `OTEL_EXPORTER_OTLP_ENDPOINT` | *(unset)* | OpenTelemetry OTLP collector URL |
| Bearer (subprocess) | `AGENTGUARD_BEARER` | *(unset)* | Bearer token forwarded by the TS SDK; honored by `agentguard-server` |
| Traceparent (subprocess) | `AGENTGUARD_TRACEPARENT` | *(unset)* | W3C trace context forwarded by the TS SDK; applied to the in-process request |

Console-specific environment (`AGENTGUARD_OIDC_*`, `AGENTGUARD_SESSION_SECRET`, …) is documented in [`frontend/README.md`](frontend/README.md).

## Examples

[`examples/`](examples/) contains working examples:

- [`examples/strands-tool-authz/`](examples/strands-tool-authz/) — Strands Agents (TypeScript) agent whose tool calls are guarded by the AuthZEN PDP via a `BeforeToolCallEvent` hook
- [`examples/rust-embedder/`](examples/rust-embedder/) — Rust app that mounts the AuthZEN PDP router inside an existing axum application via `agentguard_server::build_router`

See [`examples/README.md`](examples/README.md) for the index.

The admin console under [`frontend/`](frontend/) doubles as an interactive walkthrough: simulate authorizations, browse the audit log, and issue delegated tokens. It requires OIDC sign-in (viewer/admin roles) and fails closed with `503` when authentication is not configured.

## Architecture

See [`docs/architecture.md`](docs/architecture.md).

```text
your app / agent ──► SDK │ CLI │ console ──► agentguard-core (Cedar engine) ──► decision + audit record
                                  └──────► agentguard-server (AuthZEN HTTP PDP) ──┘
```

### Standards Implemented

- **Cedar** 4.x — authorization policy language
- **OpenID AuthZEN** WG draft — PDP/PEP interop protocol
- **W3C Trace Context** — distributed tracing propagation
- **RFC 7519** (JWT) + **RFC 8725** (JWT BCP) — token validation
- **RFC 8414** (OAuth 2.0 Authorization Server Metadata) — OIDC discovery
- **RFC 8693** (OAuth 2.0 Token Exchange) — agent-to-agent delegation
- **RFC 8707** (Resource Indicators) — audience restriction
- **RFC 9449** (DPoP) — sender-constrained tokens
- **SPIFFE X.509-SVID** — workload identity

## Project Structure

```text
agent-guard/
├── crates/
│   ├── agentguard-core/         # Type-safe wrappers, decision cache, audit log
│   ├── agentguard-cli/          # `agentguard` CLI binary
│   ├── agentguard-telemetry/    # OTel/OTLP sink trait + Prometheus metrics
│   ├── agentguard-auth/         # JWT/OIDC/API-key/DPoP/SPIFFE
│   ├── agentguard-redis-store/  # Shared Redis-compatible REST adapters
│   ├── agentguard-policy/       # Versioned bundles, policy operations, blast radius
│   └── agentguard-server/       # AuthZEN HTTP PDP
├── typescript/
│   └── agentguard/              # TypeScript SDK
├── frontend/                    # Next.js 16 admin console (shadcn/ui)
├── site/                        # Astro 7 product landing page (GitHub Pages)
├── examples/                    # Working examples (TS + Rust embedder)
├── schemas/                     # Cedar schema fragments
└── docs/                        # Guides, architecture, API, and operations documentation
```

## Development

```bash
# Format + lint + test (mirror CI)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Build everything
cargo build --workspace --release

# Cargo.lock is committed so two clones of the same commit produce
# identical binaries. Bump deps with:
#   cargo update -p <crate>
# then open a focused PR per crate.

# TypeScript workspace (SDK, frontend, examples)
pnpm install
pnpm --filter agentguard test
pnpm --filter frontend dev      # console at http://localhost:3000

# Run the Strands example
pnpm --filter strands-tool-authz start
```

We use [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat: add step-up auth flow to TypeScript SDK
fix: clamp TTL to configured maximum in decision cache
docs: document RFC 9449 DPoP binding
refactor: extract hash-chain HMAC to a dedicated module
test: add adversarial Cedar policy fixtures
chore: bump cedar-policy to 4.4
```

## Testing

```bash
cargo test --workspace             # Rust unit + integration tests
cargo test --workspace --all-features
pnpm --filter agentguard test      # TypeScript SDK
pnpm --filter frontend lint        # Frontend console lint
node frontend/scripts/e2e.mjs      # Production console e2e (mock IdP/PDP/Redis REST/CLI)
```

## Build

```bash
cargo build --workspace --release
pnpm check                          # public/docs/site/frontend checks
pnpm build                          # SDK, frontend, examples, and site
```

## Release

```bash
# Bump workspace version in Cargo.toml, update CHANGELOG.md, then:
git tag vX.Y.Z && git push origin vX.Y.Z
# CI validates the tag, publishes versioned GHCR images, and attaches their
# immutable digests to the GitHub release.
```

The release workflow publishes `linux/amd64` images to GitHub Container
Registry as `ghcr.io/<owner>/<repo>-server` and
`ghcr.io/<owner>/<repo>-console`. Confirm both packages are public before
announcing a release, then deploy their recorded digests rather than mutable
tags. Operators may build and push to another registry using the
[deployment guide](docs/kubernetes.md#build-and-publish). Rust workspace
crates remain source-distributed and are not published to crates.io.

## Tech Stack

| Category | Technology |
| -------- | ---------- |
| Core language | Rust (edition 2021) |
| Policy engine | [cedar-policy](https://github.com/cedar-policy/cedar) 4.x |
| CLI parsing | [clap](https://github.com/clap-rs/clap) 4 |
| Async runtime | [tokio](https://tokio.rs/) |
| Serialization | [serde](https://serde.rs/), [serde_json](https://github.com/serde-rs/json) |
| Tracing | [tracing](https://github.com/tokio-rs/tracing) + OTLP |
| Crypto | [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek), [hmac](https://github.com/RustCrypto/MACs), [sha2](https://github.com/RustCrypto/hashes) |
| File watching | [notify](https://github.com/notify-rs/notify) |
| HTTP client | [reqwest](https://github.com/seanmonstar/reqwest) (rustls) |
| TypeScript SDK | Node.js ≥ 20.9, [zod](https://zod.dev), native `fetch` |
| Frontend | Next.js 16, React 19.2, [shadcn/ui](https://ui.shadcn.com), Tailwind CSS v4, [jose](https://github.com/panva/jose) |
| Build (TypeScript) | [tsc](https://www.typescriptlang.org/), Turbopack |

## Roadmap

The current supported baseline is Docker plus Kubernetes with the shipped PDP,
console, atomic policy reload, persistent audit volume, and Redis-compatible
console rate limiting. Future work includes policy A/B testing, multi-tenant
audit namespaces, and a stable API/LTS support window. See
[CHANGELOG.md](CHANGELOG.md) for shipped changes; no roadmap item is a current
production guarantee.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Code of Conduct

This project follows the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md).

## Documentation site

The product landing page is published at <https://sachncs.github.io/agent-guard/>.

The site lives under [`site/`](site/) as a standalone Astro 7 + Tailwind v4
project. It is built and deployed by the
[`.github/workflows/deploy-site.yml`](.github/workflows/deploy-site.yml) workflow
on every push to `master`. The Pages source is configured to **GitHub Actions**,
so no branch-based publishing is involved.

```bash
cd site
pnpm install --frozen-lockfile
pnpm build                         # → site/dist/
pnpm preview                       # local preview
```

The repository bootstrap (`./scripts/setup.sh`) installs both the root
workspace and this separately locked site workspace.

The full repository setup requires Node.js ≥ 22.12 and pnpm 11.22.x. The standalone TypeScript SDK supports Node.js ≥ 20.9.

## Security

Please **do not** file security vulnerabilities as public GitHub issues. Report vulnerabilities to **sachncs@gmail.com** — see [SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE) © 2026 Sachin

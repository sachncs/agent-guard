<p align="center">
  <h1 align="center">agentguard</h1>
  <p align="center">Cedar-powered authorization for AI agents — per-tool-call decisions, tamper-evident audit, scoped delegation.</p>
  <p align="center">
    <a href="#installation"><img src="https://img.shields.io/badge/rust-1.85%2B-orange" alt="Rust"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
    <a href="https://github.com/sachncs/agent-guard/actions"><img src="https://img.shields.io/github/actions/workflow/status/sachncs/agent-guard/ci.yml?branch=master" alt="CI"></a>
    <a href="https://crates.io/crates/agentguard-core"><img src="https://img.shields.io/crates/v/agentguard-core" alt="crates.io"></a>
    <a href="https://github.com/sachncs/agent-guard/stargazers"><img src="https://img.shields.io/github/stars/sachncs/agent-guard" alt="Stars"></a>
  </p>
</p>

**agentguard wraps [Cedar](https://www.cedarpolicy.com) — a policy language with formal verification support — and adds the agent-specific, enterprise-specific primitives you need.**

Every tool call is an explicit authorization decision. Every decision is tamper-evident, traced end-to-end, and bound to a short-lived identity: tokens are JWS-signed, policies are versioned and hot-reloaded, and the engine speaks the [OpenID AuthZEN](https://openid.github.io/authzen/) interop standard.

## How It Works

```text
tool call ──► intercept (SDK / HTTP PDP) ──► evaluate Cedar policies ──► Allow │ Deny
                                                │
                                     every decision recorded
                                                ▼
                        hash-chained audit log (CEF / LEEF / ECS / JSONL export)
```

Each request carries a principal (`User::"alice"` or `Agent::"research"`), an action (`ToolCall::send_email`), a resource (`Mailbox::"alice@acme"`), and context (`session`, tool `args`). Policies in `.agentguard/policies/*.cedar` are evaluated against the schema plus per-request entities — allow runs the tool, deny raises `AuthorizationDenied` back to the model.

## Features

- **Per-call authorization** — does this user/agent have permission to call this tool on this resource, right now, with this context?
- **Tamper-evident audit trail** — hash-chained decision log, exportable to your SIEM in CEF/LEEF/ECS/JSONL
- **Scoped delegation** — parent agent gives a sub-agent a *scoped subset* of permissions, time-boxed, sender-constrained (DPoP), revocable
- **Schema-validated policies** — security teams write Cedar, not imperative code; validated at authoring time
- **Standard authn** — JWT, OIDC, API keys, DPoP, SPIFFE; RFC 8725 BCP crypto, RFC 8693 delegation, no proprietary protocols
- **OpenTelemetry-native observability** — every decision is a span with `authz.*` attributes and a metric
- **Hot reload + rollback + blast radius** — push policies without downtime; see what would break before you push
- **AuthZEN-compatible PDP** — works with every AuthZEN-aware gateway, federation tool, and replacement PDP
- **Local-first** — files in `.agentguard/` are the source of truth; `git diff` your policies; run in-process or as a sidecar
- **Admin console** — Next.js dashboard with OIDC sign-in, policy simulator, delegation management, audit browser

## Components

| Component | Purpose |
| --------- | ------- |
| `agentguard-core` (Rust) | Type-safe wrappers, decision cache, hash-chained audit log, TTL primitives |
| `agentguard` CLI | `init`, `validate`, `authorize`, `sim`, `delegate`, `verify`, `audit`, `policy`, `serve`, `doctor` |
| `agentguard-telemetry` (Rust) | Pluggable `Sink` trait, OTel/OTLP, Prometheus metrics |
| `agentguard-auth` (Rust) | JWT (RFC 7519 + RFC 8725), OIDC (RFC 8414), API keys, DPoP (RFC 9449), SPIFFE/SPIRE, jti replay protection, RFC 8693 token exchange |
| `agentguard-policy` (Rust) | Versioned bundles, file watcher, hot reload, diff, blast radius, dry-run |
| `agentguard-server` (Rust) | `agentguard serve` — AuthZEN HTTP PDP, sidecar mode |
| `agentguard` (TypeScript SDK) | In-process bindings via the CLI, JWT/DPoP passthrough, step-up auth |
| `frontend` (Next.js 16 console) | Dashboard, policy simulator, delegation console (shadcn/ui) |

See [CHANGELOG.md](CHANGELOG.md) for the complete change list. The implementation plan lives in [`stages/`](stages/README.md).

## Surfaces

All four integration surfaces converge on the same Cedar engine and the same audit log:

| Surface | Integration | Best for |
| ------- | ----------- | -------- |
| TypeScript SDK | Spawns the CLI in-process | Node.js agents (Strands, LangChain, custom loops) |
| HTTP PDP | AuthZEN `POST /access/v1/evaluation` | Any language, gateways, sidecar deployments |
| CLI | Subprocess invocation | Scripts, CI checks, local evaluation |
| Admin console | Web UI over both | Security/ops teams simulating and delegating |

## Installation

### CLI (Rust)

```bash
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

**Requirements:** Rust 1.89+, Node.js ≥ 20.9 (26 recommended), pnpm ≥ 9.

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
agentguard serve \
    --listen tcp://0.0.0.0:8443 \
    --tls-cert ./server.pem --tls-key ./server.key \
    --store ./.agentguard \
    --audit .audit/decisions.jsonl
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

// Scoped delegation (RFC 8693-style, JWS-signed, time-boxed):
client.delegate(
  'Agent::"research"',
  'Agent::"summarizer"',
  ["ToolCall::send_email"],
  ["Mailbox::*"],
  300,
);
```

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
| gRPC listen | `--grpc-listen` / `AGENTGUARD_GRPC_LISTEN` | *(unset)* | Optional gRPC PDP endpoint (AuthZEN-compatible `AccessEvaluation`) |
| Auth mode | `AGENTGUARD_AUTH` | `disabled` | `apikey:<path>` enables bearer-token auth on `/access/v1/*` |
| Allow loopback bypass | `AGENTGUARD_ALLOW_LOOPBACK_BYPASS` | `0` | Set `1` to allow auth-disabled on a public bind |
| Decision cache TTL | `AGENTGUARD_CACHE_TTL` | `60s` | TTL for in-memory decision cache (humantime) |
| Decision cache capacity | `AGENTGUARD_CACHE_CAPACITY` | `10000` | Max entries in the decision cache |
| JWKS refresh | `AGENTGUARD_JWKS_REFRESH` | `30s` | Cached JWKS refresh interval (humantime) |
| OTLP endpoint | `OTEL_EXPORTER_OTLP_ENDPOINT` | *(unset)* | OpenTelemetry OTLP collector URL |

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
│   ├── agentguard-policy/       # Versioned bundles, hot reload, blast radius
│   └── agentguard-server/       # AuthZEN HTTP PDP
├── typescript/
│   └── agentguard/              # TypeScript SDK
├── frontend/                    # Next.js 16 admin console (shadcn/ui)
├── examples/                    # Working examples (TS + Rust embedder)
├── schemas/                     # Cedar schema fragments
├── docs/                        # Architecture & API documentation
└── stages/                      # Stage-by-stage implementation plan
```

## Development

```bash
# Format + lint + test (mirror CI)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Build everything
cargo build --workspace --release

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
node frontend/scripts/e2e.mjs      # Full console e2e (mock IdP/PDP/CLI)
```

## Build

```bash
cargo build --workspace --release
pnpm -r build                      # SDK, frontend, examples
```

## Release

```bash
# Bump workspace version in Cargo.toml, update CHANGELOG.md, then:
git tag vX.Y.Z && git push origin vX.Y.Z
# CI publishes Rust crates and the TypeScript package
```

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
| TypeScript SDK | Node.js ≥ 20.9 (26 recommended), [zod](https://zod.dev), native `fetch` |
| Frontend | Next.js 16, React 19.2, [shadcn/ui](https://ui.shadcn.com), Tailwind CSS v4, [jose](https://github.com/panva/jose) |
| Build (TypeScript) | [tsc](https://www.typescriptlang.org/), Turbopack |

## Roadmap

- **v0.3.0** — Current: Python SDK removed (TypeScript SDK + AuthZEN PDP are the supported integration paths), hardened Next.js 16 admin console (OIDC + RBAC, fail-closed), Strands Agents example, Google TS style-guide compliance
- **v0.4.0** — Planned: distributed decision cache (Redis), policy A/B testing, multi-tenant audit namespaces, OpenTelemetry collector integration
- **v1.0.0** — Stable API, semantic-versioning guarantees, LTS support window

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Code of Conduct

This project follows the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md).

## Security

Please **do not** file security vulnerabilities as public GitHub issues. Report vulnerabilities to **sachncs@gmail.com** — see [SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE) © 2026 Sachin

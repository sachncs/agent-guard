<p align="center">
  <h1 align="center">agentguard</h1>
  <p align="center">Enterprise-grade Cedar-powered authorization for AI agents.</p>
  <p align="center">
    <a href="#installation"><img src="https://img.shields.io/badge/rust-1.85%2B-orange" alt="Rust"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
    <a href="https://github.com/sachncs/agent-guard/actions"><img src="https://img.shields.io/github/actions/workflow/status/sachncs/agent-guard/ci.yml?branch=master" alt="CI"></a>
    <a href="https://crates.io/crates/agentguard-core"><img src="https://img.shields.io/crates/v/agentguard-core" alt="crates.io"></a>
    <a href="https://github.com/sachncs/agent-guard/stargazers"><img src="https://img.shields.io/github/stars/sachncs/agent-guard" alt="Stars"></a>
  </p>
</p>

**agentguard** wraps [Cedar](https://www.cedarpolicy.com) — an
open-source policy language designed for these requirements, with formal
verification support — and adds the agent-specific, enterprise-specific
primitives you need. Every tool call is an explicit authorization
decision. Every decision is tamper-evident, traced end-to-end, and bound
to a short-lived identity. Tokens are JWS-signed, policies are versioned
and hot-reloaded, and the engine speaks the
[OpenID AuthZEN](https://openid.github.io/authzen/) interop standard.

```
┌────────────────────────────────────────────────────────────────┐
│                    your agent / service                       │
│   ┌──────────────┐    ┌────────────────┐    ┌───────────────┐ │
│   │ LangChain /  │ →  │  agentguard    │ →  │ cedar-policy  │ │
│   │ Vercel AI /  │    │  SDK (Py/TS)   │    │   + Cedar     │ │
│   │ raw HTTP     │    │  in-process or │    │   schema      │ │
│   └──────────────┘    │  subprocess    │    └───────────────┘ │
│                       └────────────────┘             │        │
│                                │                    │        │
│                                ▼                    ▼        │
│                       ┌────────────────────────────────┐    │
│                       │   agentguard-server (PDP)       │    │
│                       │   AuthZEN HTTP + gRPC           │    │
│                       └────────────────────────────────┘    │
│                                │                             │
│                                ▼                             │
│              ┌──────────────────────────────────┐            │
│              │  hash-chained audit log           │            │
│              │  CEF / LEEF / ECS / JSONL         │            │
│              │  W3C trace context per decision   │            │
│              └──────────────────────────────────┘            │
└────────────────────────────────────────────────────────────────┘
```

---

## Features

- **Per-call authorization** — does this user/agent have permission to call this tool on this resource, right now, with this context?
- **Tamper-evident audit trail** — every decision recorded, hash-chained, exportable to your SIEM in CEF/LEEF/ECS.
- **Scoped delegation** — parent agent gives sub-agent a *scoped subset* of permissions, time-boxed, sender-constrained (DPoP), revocable.
- **Schema-validated policies** — your security team writes Cedar, not imperative code. Policies are validated at authoring time.
- **Standard authn** — JWT, OIDC, API keys, DPoP, SPIFFE. RFC 8725 BCP for crypto. RFC 8693 for delegation. No proprietary protocols.
- **OpenTelemetry-native observability** — every decision is a span with `authz.*` attributes; every decision is a metric.
- **Hot reload + rollback + blast radius** — push policies without downtime; see what would break before you push.
- **AuthZEN-compatible PDP** — works with every AuthZEN-aware gateway, federation tool, and replacement PDP.
- **Local-first** — files in `.agentguard/` are the source of truth. `git diff` your policies. Run the server in-process or as a sidecar.
- **Multi-language SDKs** — Rust core, Python (`agentguard`, `agentguard_langchain`, `agentguard_server_sdk`), TypeScript (`agentguard`, `@agentguard/vercel-ai`, `@agentguard/server-sdk`).

---

## What's in v0.2.0

| Component | Purpose |
|---|---|
| `agentguard-core` (Rust) | Type-safe wrappers, decision cache, hash-chained audit log, TTL primitives |
| `agentguard` CLI | `init`, `validate`, `authorize`, `sim`, `delegate`, `verify`, `audit`, `policy`, `serve`, `doctor` |
| `agentguard-telemetry` (Rust) | Pluggable `Sink` trait, OTel/OTLP, Prometheus metrics |
| `agentguard-auth` (Rust) | JWT (RFC 7519 + RFC 8725), OIDC (RFC 8414), API keys, DPoP (RFC 9449), SPIFFE/SPIRE, jti replay protection, RFC 8693 token exchange |
| `agentguard-policy` (Rust) | Versioned bundles, file watcher, hot reload, diff, blast radius, dry-run |
| `agentguard-server` (Rust) | `agentguard serve` — AuthZEN HTTP + gRPC PDP, sidecar mode |
| `agentguard` (Python SDK) | In-process or subprocess mode, JWT/DPoP passthrough, step-up auth, traceparent |
| `agentguard-langchain` (Python) | Middleware for every LangChain tool call, surfaces step-up |
| `agentguard` (TypeScript SDK) | Mirror of Python SDK |
| `@agentguard/vercel-ai` (TS) | Middleware for Vercel AI SDK tool calls |
| `@agentguard/server-sdk` (TS) | AuthZEN client for talking to `agentguard serve` |

See [CHANGELOG.md](CHANGELOG.md) for the complete v0.2.0 change list.
The implementation plan lives in [`stages/`](stages/README.md).

---

## Installation

### CLI (Rust)

```bash
cargo install --path crates/agentguard-cli
```

### Python SDK + LangChain + Server SDK

```bash
pip install -e python/agentguard
pip install -e python/agentguard_langchain
pip install -e python/agentguard_server_sdk
```

### TypeScript SDKs

```bash
cd typescript/agentguard && npm install && npm run build
cd typescript/packages/vercel-ai && npm install && npm run build
```

**Requirements:** Rust 1.85+, Python 3.10+, Node.js ≥ 20.

---

## Quick Start

### Initialize a project

```bash
mkdir my-agent && cd my-agent
agentguard init --name acme
```

This creates:

```
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
# ✓ ALLOW alice send_email alice@acme
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
    --auth jwt=https://idp.example.com \
    --audit .audit/decisions.jsonl
```

Server is now speaking [AuthZEN](https://openid.github.io/authzen/):

```bash
curl -X POST https://localhost:8443/access/v1/evaluation \
    -H "Authorization: Bearer $JWT" \
    -H "Content-Type: application/json" \
    -d '{
      "subject":  {"type": "User", "id": "alice"},
      "action":   {"type": "Action", "id": "ToolCall::send_email"},
      "resource": {"type": "Mailbox", "id": "alice@acme"},
      "context":  {"args": {"to": "[email protected]"}, "session": {"ip": "10.0.0.1", "mfa": true}}
    }'
# {"decision": true, ...}
```

### Python SDK

```python
from agentguard import (
    Client, Principal, AgentAction, Resource, Context,
    BearerAuth, DpopKey,
)

client = Client(
    store=".agentguard",
    mode="in_process",                 # uses cedar-policy bindings (fast)
    auth=BearerAuth(token=os.environ["JWT"]),
    traceparent="00-aaaa...bbbb-01",    # optional W3C trace context
)

# Will raise AuthorizationDenied on Deny.
client.check(
    Principal.user("alice"),
    AgentAction.tool("send_email"),
    Resource("Mailbox", "alice@acme"),
    Context(args={"to": "[email protected]"}, session={"ip": "10.0.0.1", "mfa": True}),
)

# Step-up auth (MFA required) surfaces as an exception:
# agentguard.errors.StepUpRequired(acr_values=..., amr_values="mfa hwk")
```

### LangChain middleware

```python
from langchain.agents import initialize_agent, AgentType
from langchain_openai import OpenAI
from langchain_community.tools import DuckDuckGoSearchRun

from agentguard_langchain import GuardConfig, GuardedTool, Principal

search = GuardedTool(
    DuckDuckGoSearchRun(),
    GuardConfig(
        store=".agentguard",
        principal_factory=lambda runtime: Principal.user("alice"),
        on_step_up=lambda step_up: trigger_mfa_flow(step_up),
    ),
)

agent = initialize_agent([search], OpenAI(), agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION)
agent.run("Search for the latest Cedar policy tutorials")
```

### Multi-agent delegation (JWS, RFC 8693)

```python
token = client.delegate(
    from_principal='Agent::"research"',
    to='Agent::"summarizer"',
    audience="agentguard://prod/email",  # required (RFC 8707)
    actions=["ToolCall::send_email"],
    resources=["Mailbox::*"],
    constraints=[{"path": "context.args.amount", "op": "lt", "value": 10000}],
    ttl_seconds=300,
)
# JWS compact: eyJhbGciOiJFZERTQSIs...
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
# ⚠ JWT validator configured but jwks_uri unreachable (cached 30s)
```

---

## Configuration

| Setting | Flag / Env | Default | Description |
|---------|------------|---------|-------------|
| Audit log path | `--audit` | `./.audit/decisions.jsonl` | Hash-chained audit log destination |
| Chain secret | `--secret-file` | `./.chain-secret` | HMAC key for the audit chain |
| Auth provider | `--auth jwt=...` / `--auth api-key=...` | `none` | Authentication provider |
| Listen address | `--listen` | `tcp://127.0.0.1:8443` | Server listen address |
| Store path | `--store` | `./.agentguard` | Cedar schema and policy directory |
| Decision cache TTL | `AGENTGUARD_CACHE_TTL` | `60s` | TTL for in-memory decision cache |
| JWKS refresh | `AGENTGUARD_JWKS_REFRESH` | `30s` | Cached JWKS refresh interval |
| OTLP endpoint | `OTEL_EXPORTER_OTLP_ENDPOINT` | *(unset)* | OpenTelemetry OTLP collector URL |

---

## Examples

[`examples/`](examples/) — 7 working examples:

- `examples/basic-tool-authz/` — minimum viable authorization with audit
- `examples/multi-agent-delegation/` — parent → sub-agent JWS delegation
- `examples/nl-policy-gen/` — natural language → Cedar generation
- `examples/jwt-auth/` — bearer-token authentication (added in v2)
- `examples/oidc-discovery/` — OIDC metadata + JWKS refresh (added in v2)
- `examples/dpop-protected/` — sender-constrained tokens (added in v2)
- `examples/hash-chain-verify/` — audit log tamper detection (added in v2)

---

## Architecture

See [`docs/architecture.md`](docs/architecture.md).

### Standards implemented

- **Cedar** 4.x — authorization policy language
- **OpenID AuthZEN** WG draft — PDP/PEP interop protocol
- **W3C Trace Context** — distributed tracing propagation
- **RFC 7519** (JWT) + **RFC 8725** (JWT BCP) — token validation
- **RFC 8414** (OAuth 2.0 Authorization Server Metadata) — OIDC discovery
- **RFC 7662** (OAuth 2.0 Token Introspection)
- **RFC 7009** (OAuth 2.0 Token Revocation)
- **RFC 8693** (OAuth 2.0 Token Exchange) — agent-to-agent delegation
- **RFC 8707** (Resource Indicators) — audience restriction
- **RFC 9449** (DPoP) — sender-constrained tokens
- **RFC 8785** (JSON Canonicalization Scheme) — hash chain input
- **SPIFFE X.509-SVID** — workload identity
- **NIST SP 800-204** alignment — microservices security patterns

---

## Project Structure

```
agent-guard/
├── crates/
│   ├── agentguard-core/         # Type-safe wrappers, decision cache, audit log
│   ├── agentguard-cli/          # `agentguard` CLI binary
│   ├── agentguard-telemetry/    # OTel/OTLP sink trait + Prometheus metrics
│   ├── agentguard-auth/         # JWT/OIDC/API-key/DPoP/SPIFFE
│   ├── agentguard-policy/       # Versioned bundles, hot reload, blast radius
│   └── agentguard-server/       # AuthZEN HTTP + gRPC PDP
├── python/
│   ├── agentguard/              # Python SDK
│   ├── agentguard_langchain/    # LangChain middleware
│   └── agentguard_server_sdk/   # AuthZEN client
├── typescript/
│   ├── agentguard/              # TypeScript SDK
│   └── packages/
│       ├── vercel-ai/           # @agentguard/vercel-ai
│       └── server-sdk/          # @agentguard/server-sdk
├── examples/                    # 7 working examples
├── schemas/                     # Cedar schema fragments
├── docs/                        # Architecture & API documentation
└── stages/                      # Stage-by-stage implementation plan
```

---

## Development

```bash
# Format + lint + test (mirror CI)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Build everything
cargo build --workspace --release

# Python SDK
cd python/agentguard
pip install -e ".[dev]"
pytest

# TypeScript SDK
cd typescript/agentguard
npm install
npm test
npm run build

# Run a single example
python examples/basic-tool-authz/main.py
```

### Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add step-up auth flow to Python SDK
fix: clamp TTL to configured maximum in decision cache
docs: document RFC 9449 DPoP binding
refactor: extract hash-chain HMAC to a dedicated module
test: add adversarial Cedar policy fixtures
chore: bump cedar-policy to 4.4
```

---

## Testing

```bash
cargo test --workspace             # Rust unit + integration tests
cargo test --workspace --all-features
cd python/agentguard && pytest     # Python SDK
cd typescript/agentguard && npm test  # TypeScript SDK
```

---

## Build

```bash
cargo build --workspace --release
cd typescript/agentguard && npm run build
cd typescript/packages/vercel-ai && npm run build
```

---

## Release

1. Bump workspace version in `Cargo.toml`
2. Update `CHANGELOG.md` with the new release notes
3. Commit with a `version:X.Y.Z` message
4. Tag and push — CI publishes Rust crates and Python/TypeScript packages

---

## Tech Stack

| Category | Technology |
|----------|------------|
| Core language | Rust (edition 2021) |
| Policy engine | [cedar-policy](https://github.com/cedar-policy/cedar) 4.x |
| CLI parsing | [clap](https://github.com/clap-rs/clap) 4 |
| Async runtime | [tokio](https://tokio.rs/) |
| Serialization | [serde](https://serde.rs/), [serde_json](https://github.com/serde-rs/json) |
| Tracing | [tracing](https://github.com/tokio-rs/tracing) + OTLP |
| Crypto | [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek), [hmac](https://github.com/RustCrypto/MACs), [sha2](https://github.com/RustCrypto/hashes) |
| File watching | [notify](https://github.com/notify-rs/notify) |
| HTTP client | [reqwest](https://github.com/seanmonstar/reqwest) (rustls) |
| Python SDK | Python 3.10+, Pydantic v2, [httpx](https://www.python-httpx.org/) |
| TypeScript SDK | Node.js ≥ 20, [zod](https://zod.dev), native `fetch` |
| Build (Python) | [Hatchling](https://hatch.pypa.io/) |
| Build (TypeScript) | [tsc](https://www.typescriptlang.org/) |

---

## Roadmap

- **v0.2.0** — Current: AuthZEN HTTP + gRPC PDP, JWT/OIDC/API-key/DPoP/SPIFFE auth, RFC 8693 token exchange, hash-chained audit log + SIEM formatters, TTL & decision cache, CLI (init/validate/authorize/sim/delegate/verify/audit/policy/serve/doctor)
- **v0.3.0** — Planned: distributed decision cache (Redis), policy A/B testing, multi-tenant audit namespaces, OpenTelemetry collector integration
- **v1.0.0** — Stable API, semantic-versioning guarantees, LTS support window

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Code of Conduct

This project follows the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md).

## Security

Please **do not** file security vulnerabilities as public GitHub
issues. Report vulnerabilities to **sachncs@gmail.com** — see
[SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE) © 2026 Sachin
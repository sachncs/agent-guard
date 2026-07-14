# Changelog

All notable changes to agentguard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned for v2.0.0

See `stages/STAGE-0-style-and-architecture.md` through `stages/STAGE-9-ci-and-tooling.md`
for the detailed implementation plan.

#### Added
- **Telemetry crate** (`agentguard-telemetry`): pluggable observability layer
  with `Sink` trait, JSONL/stdout sinks, OpenTelemetry/OTLP export behind feature flag
- **Auth crate** (`agentguard-auth`): JWT validation (RFC 7519 + RFC 8725 BCP),
  OIDC discovery (RFC 8414), API keys (Stripe-style + Argon2id), DPoP (RFC 9449),
  SPIFFE/SPIRE X509-SVID verification, token introspection (RFC 7662),
  token revocation (RFC 7009), jti replay protection, RFC 8693 token exchange
- **Policy operations crate** (`agentguard-policy`): versioned bundles with
  Ed25519 signing, file watcher with debounced hot reload, policy diff,
  blast-radius analysis, dry-run/shadow mode, rollback
- **Server crate** (`agentguard-server`): `agentguard serve` binary,
  AuthZEN-compatible HTTP endpoints (`/access/v1/evaluation`, `/access/v1/evaluations`),
  gRPC PDP service via tonic, sidecar mode over Unix socket, mTLS support,
  `/healthz`, `/readyz`, `/metrics` endpoints
- **Hash-chained audit log**: HMAC-SHA256 chain over all decisions,
  canonical JSON (RFC 8785), `agentguard audit verify/notarize/sar/erase/export`
- **Decision cache with TTL**: in-process LRU + optional Redis backend,
  policy-version invalidation, per-action TTL annotations, schema-aware cache keys
- **Step-up authentication** (RFC 9470): `acr_values`/`amr_values` returned
  on decisions where MFA or stronger auth is required
- **W3C Trace Context propagation**: `traceparent`/`tracestate` header parsing
  in SDKs, threaded through requests, surfaced on decision records
- **Structured audit formatters**: CEF, LEEF, ECS for SIEM ingestion
- **Per-policy effects**: each decision now carries which policies
  allowed/denied individually (not just the aggregate)
- **Typed IDs**: `PrincipalId`, `ActionId`, `ResourceId` newtypes prevent
  cross-type mixups in the request pipeline
- **`Clock` trait**: pluggable time source for testable TTL semantics
- **In-process SDK mode**: Python and TypeScript SDKs can use
  `cedar-policy` bindings directly (no subprocess) for 10–100x speedup
- **Vercel AI SDK middleware**: drop-in authz for Vercel's AI SDK
- **OpenID AuthZEN WG compatibility**: server speaks the interop standard
- **`agentguard doctor`**: deployment health check with ✓/✗/⚠ diagnostics
- **GitHub Actions CI**: fmt, clippy, test, doc, build, Python, TypeScript,
  example smoke tests — required status check

#### Changed
- **Delegation tokens**: switched from custom compact format
  (`payload.sig.kid`) to standard JWS (RFC 7515) with EdDSA/ES256/RS256
  algorithm agility (RFC 8725 §3.1)
- **Delegation claims**: `DelegationConfig.ttl_seconds: i64` → `ttl: Duration`;
  gains structured `constraints` (path-based Equals/In/GreaterThan/LessThan/Glob/And/Or/Not);
  gains `act` claim chain per RFC 8693 for User → Agent → SubAgent hierarchies
- **Error variants**: `Error::TokenSignatureInvalid` → `Error::TokenSignature { reason }`;
  `Error` enum is now `#[non_exhaustive]`
- **DecisionRecord schema**: gains `chain_id`, `prev_hash`, `record_hash`,
  `tenant_id`, `subject_id`, `data_categories`, `legal_basis`, `retention_class`,
  `trace_id`, `span_id`, `step_up`, `cached`, `policy_effects`
- **Time fields**: all `i64` seconds replaced with `std::time::Duration`
  (TTL knobs) or `Timestamp` newtype (absolute times)
- **Module layout**: `request.rs` split into `principal.rs`/`action.rs`/
  `resource.rs`/`context.rs`/`request.rs`; `authorize.rs`, `decision.rs`,
  `policy.rs` become directories with submodules

#### Removed
- **v1 compact delegation token format** (`payload.sig.kid`); JWS only
- **`ActionDef` empty stub** in core
- **`KeyBundle` unused struct** in delegation
- **`Error::Cedar(String)`** unused variant
- **`_schema_anchor` no-op** in CLI

#### Security
- **JWT verification**: algorithm whitelist per RFC 8725 BCP, no `alg: none`,
  no HS↔RS confusion attacks (CVE-2015-9235)
- **DPoP**: sender-constrained tokens (RFC 9449) prevent bearer-token theft;
  default for fintech/banking-grade deployments
- **JTI replay protection**: Bloom-filter-backed tracker prevents token replay
- **Key rotation grace period**: 7-day overlap window for zero-downtime rotation
- **Audience restriction**: tokens scoped per RFC 8707 resource indicators
- **Hash-chained audit log**: tamper-evident (SOC 2 CC7.2 compliant)
- **Tamper-evident policy bundles**: Ed25519-signed policy versions

#### Compliance
- **SOC 2 CC7.2**: hash-chained audit log
- **GDPR Art. 5/15/17/30**: data_categories, subject access (`sar`), erasure
  (pseudonymization), records of processing fields
- **RFC 8725 JWT BCP**: algorithm agility, key confusion prevention
- **RFC 9449 DPoP**: FAPI 2.0 / PSD3-ready sender-constrained tokens
- **RFC 8693 Token Exchange**: standard agent-to-agent delegation

### Deferred to future versions (v2.1.0+)
- HSM-backed signing keys (PKCS#11 / AWS Nitro Enclaves)
- Multi-region active-active policy replication
- Hosted control plane for policy distribution (Cerbos-Hub-style)
- OpenFGA / Zanzibar adapter for relationship-style checks
- DPoP outbound (minting agent tokens, not just verification)
- A/B testing UI
- Sandbox SAML provider for offline testing

## [0.1.0] — 2026-07-14

### Added
- **Initial v1 release**: Cedar-powered authorization primitives for AI agents
- **`agentguard-core`**: type-safe wrappers over `cedar-policy`
  (Principal, AgentAction, Resource, AgentContext, AgentRequest)
- **`agentguard` CLI**: `init`, `validate`, `authorize`, `sim`, `delegate`,
  `verify`, `schema`, `log`, `gen` subcommands
- **Decision log**: append-only JSONL audit trail
- **Delegation tokens**: Ed25519-signed, scoped, time-boxed tokens for
  parent → sub-agent delegation chains
- **NL → Cedar policy generation**: LLM with cedar-validator feedback loop
  (OpenAI + Anthropic support)
- **Python SDK**: subprocess-based wrapper with idiomatic API
- **`agentguard-langchain`**: middleware that authorizes every LangChain tool call
- **TypeScript SDK**: subprocess-based wrapper
- **Starter schema**: `User`, `Agent`, `Mailbox`, `Document`, `Repository`
  with common `ToolCall::*` actions
- **Three working examples**: basic-tool-authz, multi-agent-delegation,
  nl-policy-gen

[Unreleased]: https://github.com/sachncs/agent-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sachncs/agent-guard/releases/tag/v0.1.0
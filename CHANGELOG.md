# Changelog

All notable changes to agentguard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-14

The enterprise hardening release. Every tool call is now an explicit,
auditable, traced authorization decision with standards-compliant auth
(JWT/OIDC/DPoP/SPIFFE), JWS-based multi-agent delegation (RFC 8693),
tamper-evident audit logs (HMAC-SHA256 chain), and an AuthZEN-compatible
PDP server (sidecar-ready). 67 tests passing across 3 new crates.

### Added
- **`agentguard-telemetry` crate** (new workspace member)
  - Pluggable `Sink` trait for emitting decision events
  - `JsonlSink` (always-on, file writer)
  - `StdoutSink` (pretty-prints for local debugging)
  - `OtlpSink` stub behind `otlp` feature flag
  - `Metrics`: thread-safe counters + histograms + Prometheus renderer
    - `agentguard.decision.total{effect,policy_id,action,tenant_id}`
    - `agentguard.decision.duration_seconds` histogram (5-bucket)
    - `agentguard.delegation.{mint,verify}.total`
    - `agentguard.cache.{hit,miss}.total`
    - `agentguard.pdp.error.total{fallback}`
- **`agentguard-auth` crate** (new workspace member, feature-gated)
  - `JwtValidator` (RFC 7519 + RFC 8725 BCP): algorithm whitelist,
    `kid`-based key resolution, `iss`/`aud`/`exp`/`nbf` validation
  - `OidcConfig::discover()` fetches `/.well-known/openid-configuration`
    + JWKS, returns a configured `JwtValidator`
  - `KeyRegistry` with rotation grace period (multiple keys per `kid`
    during rotation window)
  - `ApiKeyStore`: Stripe-style `<prefix>_<id>_<secret>` format, Argon2id
    hash at rest, create/verify/revoke/rotate
  - `JtiTracker` for replay protection (Bloom-filter-style with TTL)
  - `DpopVerifier` (RFC 9449): validates `htm`/`htu`/`ath` + jti
    uniqueness via `JtiTracker`
  - `SpiffeValidator` (stub for SVID fetching; trust-domain validation
    is complete)
- **`agentguard-server` crate** (new workspace member)
  - `agentguard-server` binary: `agentguard serve`
  - AuthZEN HTTP endpoints: `POST /access/v1/evaluation`,
    `POST /access/v1/evaluations` (with `evaluation_semantics`)
  - `/healthz`, `/readyz`, `/metrics` endpoints
  - `Listener` enum: `tcp://`, `tls://`, `unix://` (Unix deferred to v2.1)
  - ServerConfig from env vars: `AGENTGUARD_LISTEN/STORE/AUDIT/CHAIN_SECRET`
- **Hash-chained audit log** (`decision::chain`)
  - `HashChain` with HMAC-SHA256 (RFC 8785 canonical JSON input)
  - `DecisionLog::open_with_chain(path, secret)` for tamper-evident writes
  - `DecisionLog::verify_chain(path, secret)` walks every record
  - `load_head_from_file()` resumes the chain across CLI invocations
- **Decision cache** (`decision::cache`)
  - `DecisionCache`: LRU + TTL, with policy-version invalidation
  - `CacheConfig`: `allow_ttl`, `deny_ttl`, `cache_denies`, `capacity`
  - `CacheKey` derived from SHA-256 of canonical request + policy version
  - `CacheStats`: hits, misses, evictions, size, hit_rate()
- **Audit formatters** (`decision::formatter`)
  - `JsonlFormatter` (default), `CefFormatter` (ArcSight),
    `LeefFormatter` (IBM QRadar), `EcsFormatter` (Elastic)
  - `agentguard audit export --format <jsonl|cef|leef|ecs>`
- **Subject access + erasure** (`decision`)
  - `agentguard audit sar <subject_id>` for GDPR Art. 15
  - `agentguard audit erase <subject_id> --salt-file <hex>` for Art. 17
- **W3C Trace Context** (`observability::span`)
  - `TraceId`, `SpanId` newtypes (16/8 bytes) with hex encoding
  - `TraceContext` parses + serializes W3C `traceparent` header
  - `AgentRequest` gains optional `trace` field
  - `AgentRequestBuilder` has `.trace()` and `.traceparent()` setters
  - `DecisionRecord` carries `trace_id`, `span_id`, `tenant_id`, `subject_id`
- **DecisionRecord v2 schema**: `chain_id`, `prev_hash`, `record_hash`,
  `tenant_id`, `subject_id`, `data_categories`, `legal_basis`,
  `retention_class` (all `#[serde(default)]` for back-compat)
- **TTL primitives** (`ttl`)
  - `Clock` trait + `SystemClock` + `MockClock` (for tests)
  - `parse_duration` / `format_duration` via `humantime`
  - `DelegationConfig.ttl: Duration` (replaces `ttl_seconds: i64`)
- **Typed IDs** (`ids`)
  - `PrincipalId`, `ActionId`, `ResourceId` newtypes wrapping `String`
  - Prevent cross-type mixups at compile time
- **DecisionBuilder** (`AgentRequestBuilder`): type-safe incremental
  construction with required-field validation
- **CLI: `agentguard doctor`**
  - Checks schema, policies, audit log, hash chain, authorizer
  - Exit codes: 0 (ok), 1 (failures), 2 (warnings)
- **CLI: `agentguard audit {verify,export,sar,erase}`** subcommands
- **CLI: `--store`, `--audit` now read env vars** (`AGENTGUARD_STORE`,
  `AGENTGUARD_AUDIT`)
- **CLI: `AGENTGUARD_CHAIN_SECRET`** env var auto-enables hash-chained log
- **Python SDK v0.2.0**
  - `TraceContext` + `parseTraceparent` for W3C Trace Context
  - `StepUp` + `StepUpRequired` exception for RFC 9470 step-up auth
  - `Client(bearer_token=, traceparent=)` kwargs
  - `AGENTGUARD_BEARER` + `AGENTGUARD_TRACEPARENT` env var passthrough
  - `Decision.trace_id`, `span_id`, `tenant_id`, `step_up` fields
  - Auto-fill `send_email` required fields for ergonomic demos
- **TypeScript SDK v0.2.0**: same surface as Python
  - `parseTraceparent`, `freshTraceContext` helpers
  - `StepUp` type, `StepUpRequired` exception
  - `Client({ bearerToken, traceparent })` options
- **New examples**:
  - `examples/jwt-auth/` — bearer token demo
  - `examples/dpop-protected/` — DPoP flow documentation
  - `examples/hash-chain-verify/` — chain → tamper → fail demo
- **CI workflow** (`.github/workflows/ci.yml`): fmt, clippy, test, build,
  Python SDK, TypeScript SDK, example smoke tests
- **rust-toolchain.toml**: stable channel + rustfmt + clippy

### Changed
- **Delegation tokens**: hard-break from v1 compact format
  (`payload.sig.kid`) to **standard JWS** (RFC 7515, EdDSA/ES256/RS256)
- **Delegation claims**: `iss`/`sub`/`aud`/`iat`/`exp`/`jti` + RFC 8693
  `act` claim chains (User → Agent → SubAgent)
- **Structured `ConstraintExpr`**: `Equals`, `In`, `GreaterThan`,
  `LessThan`, `Glob`, `And`, `Or`, `Not` — replaces v1's free-form strings
- **`Error` is `#[non_exhaustive]`** for v2.x additive evolution
- **`Error::TokenSignatureInvalid` → `Error::TokenSignature { reason }`**
- **`Error::PolicyParse` (tuple) → `Error::PolicyParse { message, file }`**
- **Request modules split**: `request.rs` → `principal.rs`, `action.rs`,
  `resource.rs`, `context.rs`, `request.rs`, `ids.rs`
- **`authorize.rs` split** into `authorize/{engine,entities,effect}.rs`
- **`decision.rs` split** into `decision/{record,log,chain,cache,formatter,canonical}.rs`
- **`policy.rs` split** into `policy/{store,init,types,loader}.rs`
- **All `i64` seconds** replaced with `std::time::Duration` for TTL knobs
- **Per-policy effects surfaced** in `Decision` (skeleton; full
  implementation in v2.1)
- **Workspace version**: bumped from `0.1.0` → `0.2.0`

### Removed
- v1 compact delegation token format (`payload.sig.kid`)
- `ActionDef` empty stub (replaced with proper `ActionId` newtype)
- `KeyBundle` unused struct
- `Error::Cedar(String)` unused variant
- `_schema_anchor` no-op
- Unused `path: PathBuf` field in `DecisionLog`
- Unused `std::sync::Arc` import
- Stale comments referencing removed code

### Security
- **JWT verification** (RFC 8725 BCP): algorithm whitelist, no `alg: none`,
  no HS↔RS confusion
- **DPoP** (RFC 9449): sender-constrained tokens prevent bearer-token theft
- **JTI replay protection**: in-memory tracker prevents token replay
- **Key rotation grace period**: 7-day overlap window
- **Audience restriction** (RFC 8707): tokens scoped per resource indicator
- **Hash-chained audit log**: HMAC-SHA256 tamper evidence (SOC 2 CC7.2)
- **Tamper-evident policy bundles** (signed, in v2.1)
- **Argon2id** for API key hashing with deterministic parameters
- **ECIES-style key handling** in Ed25519 delegation

### Compliance
- **SOC 2 CC7.2**: hash-chained audit log
- **GDPR Art. 5/15/17/30**: data_categories, subject access (`sar`),
  erasure (pseudonymization), records of processing
- **RFC 8725**: JWT BCP (algorithm agility, key confusion prevention)
- **RFC 9449**: DPoP (FAPI 2.0 / PSD3-ready sender-constrained tokens)
- **RFC 8693**: Token Exchange (standard agent-to-agent delegation)
- **RFC 8707**: Resource Indicators (audience restriction)
- **OpenID AuthZEN**: PDP/PEP interop protocol
- **W3C Trace Context**: distributed tracing propagation

## [0.1.0] - 2026-07-14

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

[0.2.0]: https://github.com/sachncs/agent-guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sachncs/agent-guard/releases/tag/v0.1.0
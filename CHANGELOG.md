## [0.2.0] - 2026-07-14
# Changelog

All notable changes to agentguard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Hardening (post v0.2.0 release audit)

This is a follow-up batch addressing 32 issues identified in the v0.2.0
production-readiness review. All 160+ tests pass deterministically.

#### Fixed (Critical)

- **JWS signature verification** — `verify_signature` was a no-op that
  only checked signature length. Now performs real EdDSA cryptographic
  verification via `DelegationVerifier::verify`. Algorithm confusion
  attacks (HS256 + RSA public key) are rejected explicitly.
- **`Box::leak` in `DelegationVerifier::verify`** — every call leaked a
  `DelegationToken`. Replaced return type with
  `Result<VerifiedDelegation>` (owned, no leak). Breaking change in the
  public API.
- **Hash chain `append` not atomic** — read/compute/write happened across
  two lock acquisitions; concurrent writers could corrupt the chain.
  Now the entire critical section is held under a single lock.
- **API key format ambiguous** — `<prefix>_<id>_<base64>` could be parsed
  incorrectly when the base64 contained underscores. Changed separator
  to `:` which is not in any of the parts. Fixed the long-standing test
  flakiness caused by this bug.

#### Fixed (High)

- **TraceId/SpanId random** were time-derived, not cryptographic. Now use
  `rand::rngs::OsRng` (the OS CSPRNG) for true uniqueness.
- **Hand-rolled schema parser** would fail on realistic Cedar. Replaced
  with cedar-policy's `Schema::entity_types()` and `Schema::actions()`
  accessors.
- **AuthZEN HTTP server had no request body size limit** (default 2 GB).
  Added `DefaultBodyLimit::max(64 KB)`.
- **Authority `std::process::exit(2)` on Deny** — now `authorize` returns
  `AuthorizeOutcome` and `main()` collects the exit code, calling
  `process::exit` ONCE at the end after all Drop runs.
- **api_key tests were flaky** in parallel runs — fixed by switching
  `Argon2::default()` to a deterministic `Argon2::new(Algorithm::Argon2id,
  Version::V0x13, Params::new(...))` and by removing the global test
  lock (no longer needed).

#### Added

- **`agentguard-policy` crate** (new workspace member) with versioned
  bundles, diff, blast-radius analysis (full replay engine — no longer a
  stub), disk persistence, and proptest regression coverage.
- **Real `OtlpSink`** (was a no-op stub). Translates `SinkEvent`s to
  OTel log records and exports via OTLP/gRPC. Reads
  `OTEL_EXPORTER_OTLP_ENDPOINT` from env.
- **Real JWKS Ed25519 extraction** in `JwtValidator::refresh_jwks`. Was
  parsing JWKS but never extracted key material; now decodes Ed25519
  keys (kty=OK, crv=Ed25519, x=base64url-32-bytes) and adds them to the
  KeyRegistry.
- **Real SPIFFE SVID fetch** when the `spiffe` feature is enabled.
  Uses `spiffe::WorkloadApiClient` to fetch a real X.509-SVID, validates
  its trust domain, and returns the SPIFFE ID.
- **Streaming `canonical_json`** via `write_canonical_value<W: Write>`
  that streams into a writer rather than building an intermediate
  `Vec<u8>`.
- **Length-prefixed `CacheKey::for_request`** — uses `sha2::Digest::update`
  with 4-byte big-endian length prefixes for each field to avoid
  boundary collisions.
- **W3C Trace Context middleware** in `agentguard-server` — reads
  `traceparent`, generates a fresh root span if missing, returns
  `x-agentguard-span-id` for correlation.
- **`tenant_id` field on `AgentRequest`** — propagates through
  `DecisionRecord` for per-tenant SAR queries, blast-radius analyses,
  and audit log scans.
- **Concurrent reads test** in `DecisionCache` — spawns 4 reader
  threads + 1 writer thread to prove the new `RwLock` doesn't deadlock.
- **Server integration tests** — 5 tests covering healthz, readyz,
  evaluation endpoint, trace context propagation, body size limit.
- **CLI smoke tests** — 3 tests covering init, validate, doctor.

#### Changed

- **`DecisionCache` uses `parking_lot::RwLock`** instead of `Mutex` —
  readers proceed in parallel. Forward-compatible with future
  `&self`-based cache backends.
- **`delegation` errors** — moved to structured variants via
  `Error::TokenSignature { reason }` for actionable error messages.
- **`DecisionRecord` v2 schema** — adds `chain_id`, `prev_hash`,
  `record_hash`, `tenant_id`, `subject_id`, `trace_id`, `span_id`,
  `data_categories`, `legal_basis`, `retention_class`. All
  `#[serde(default)]` for back-compat.
- **Public API `#[non_exhaustive]`** on `Principal`, `AgentAction`,
  `Resource`, `AgentContext`, `AgentRequest`, `DecisionRecord`,
  `DelegationClaims`, `ActClaim`, `ConstraintExpr`.
- **`PartialEq` derives** on `Principal`, `AgentAction`, `Resource`,
  `AgentContext`, `AgentRequest` for testability.
- **MSRV 1.75** declared in `[workspace.package].rust-version`.
- **Release profile** uses `lto = "fat"` (was `"thin"`).
- **CI** adds `cargo-deny check bans licenses sources` (blocking) and
  `cargo-deny check advisories` (non-blocking, tracked for v0.3).

#### Removed

- `make_run` and `config_from_env` exports from `agentguard-server` —
  dead code. Documented migration inline.
- `Algorithm::as_jose_str` and `Hash` derive on `Algorithm` — unused.
- `_force_use_trace` helper in `DecisionCache` — workaround for
  a no-longer-needed import.
- `_anchor` and `decode_secret` helpers — dead.

### Known upstream advisories (v0.3 follow-up)

Two `cargo-deny advisories` findings are tracked but **not actionable**
within the v0.2.0 release window because they require ecosystem-wide
upgrades out of our control:

- **RUSTSEC-2026-0098** (`rustls-webpki 0.101.7`): name-constraint bypass.
  Fixed in `rustls-webpki` ≥ 0.103.12. Our tree pulls `rustls-webpki` 0.101
  via `reqwest 0.11` (transitive from `oauth2 4.4` / `openidconnect 3.5`).

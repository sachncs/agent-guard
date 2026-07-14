## [0.2.0] - 2026-07-14
# Changelog

All notable changes to agentguard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security hardening (pre-launch audit follow-up)

Ten critical defects and six high-severity issues identified during a
production-readiness review on the eve of v0.2.0 GA. All addressed.
Every existing test still passes; new regression tests added for
each fix. **This batch must ship before any production deployment.**

#### Fixed (Critical)

- **DPoP signature verification was a no-op (C-1)** —
  `DpopVerifier::verify` constructed a `JwtValidator` but never
  called it. Any attacker could forge a DPoP proof and have it
  accepted. Now: parses the `jwk` from the proof header, computes
  the JWK SHA-256 thumbprint per RFC 7638, requires it match the
  caller-supplied `expected_jkt` (the access token's `cnf.jkt`),
  and verifies the EdDSA signature using the `jwk`'s verifying
  key. API change: `verify()` now takes `expected_jkt: &str`.
- **OIDC discovery trusted whatever issuer the IdP returned (C-2)** —
  `OidcConfig::discover` built `JwtConfig` from `meta.issuer` without
  comparing to `self.issuer`. A MITM could substitute the trusted
  issuer and JWKS URL. Now: asserts `meta.issuer == self.issuer`
  immediately after parse, before any JWKS fetch (RFC 8414 §3.3).
- **JWT `iss` check silently skipped when claim was absent (C-3)** —
  `JwtValidator::validate` had the iss comparison inside `if let Some(iss)`,
  so a JWT with no iss claim passed signature/aud/exp checks. Now:
  iss is REQUIRED (RFC 8725 §3.1).
- **Server authorized every request against `Entities::empty()` (C-4)** —
  Every Cedar policy referencing entity attributes or hierarchies
  returned Deny. Now: `AuthZenEvaluationRequest.entities` is threaded
  into `authorize()` via `build_request_entities()`.
- **Server had no audit logging (C-7)** — `cfg.audit_log` and
  `cfg.chain_secret` were read from env but never threaded through.
  Zero decisions were written to disk. Now: `build_state()` opens
  the DecisionLog (chained if chain_secret is Some); handlers
  `append_decision()` after every authorize(). 500 responses no
  longer leak Cedar error text.
- **Chain_id drift across restarts (C-9)** — `HashChainInner.id` was
  immutable; `load_head_from_file` parsed the id from disk and
  constructed a discarded HashChain ("let _ = new;"). Every
  restart generated a fresh id; old records kept the previous id
  and verify_chain rejected the result. Now: id lives in a
  `Mutex<Option<ChainId>>`; `DecisionLog` persists it to a sidecar
  file eagerly on open and again on first append.
- **DPoP jti truncation (C-8)** — non-hex jtis (UUIDs, alphanumerics)
  decoded via `hex::decode` to 0 bytes; every subsequent DPoP
  collided on the all-zeros key, masquerading as a replay attack.
  Now: SHA-256 the jti string, take first 16 bytes.
- **Chain append not crash-safe (C-10)** — head advanced before the
  file write succeeded; on crash between the two, the in-memory
  head was one record ahead of the file. Now: single `write_all()`
  (atomic for records ≤ 4 KiB on POSIX) + `sync_all()` before
  reporting success.
- **Missing `crates/agentguard-policy/src/watcher.rs` (C-5)** —
  declared in lib.rs behind `#[cfg(feature = "watch")]` but the
  file didn't exist; `--features watch` failed to build. Added a
  minimal stub (no-op PolicyWatcher; full notify-backed
  implementation deferred to v0.3.0).
- **`audit erase` broke the chain (C-6)** — rewrote the log as bare
  `DecisionRecord`, dropping `prev_hash` / `record_hash` / `chain_id`.
  Subsequent `verify_chain` rejected the file as a chain break.
  Now: rewrites as `ChainedRecord` preserving the chain metadata,
  with a warning that the rewritten file will fail verify_chain
  (operators must keep the pre-erasure file).

#### Fixed (High)

- **`DecisionCache` was never actually switched to RwLock (H-1)** —
  commit 02ae7a8's message claimed "inner: parking_lot::Mutex →
  parking_lot::RwLock" and the CHANGELOG repeated this. The code
  was never changed. Now actually switched. Reads (the common case)
  take a shared lock; only `put()` takes the exclusive lock.
- **`KeyRegistry::add()` appended forever (H-3)** — every JWKS
  refresh added a new entry per JWKS doc key; long-running
  processes OOMed. Now replaces active entries with the same
  kid+alg; grace-window entries from `rotate()` are preserved.
- **No HTTP fetcher timeouts (H-4/H-10)** — `reqwest::get()` uses a
  default client with no timeout; a hung IdP exhausted tokio tasks.
  Now: 10 s total / 5 s connect, no redirects (SSRF guard), 1 MiB
  body cap, 64-key JWKS cap.
- **No graceful shutdown (H-5)** — server.rs never installed
  SIGTERM/SIGINT handlers; in-flight requests aborted on kill,
  dropping audit writes. Now: `with_graceful_shutdown()` on axum
  serve + axum_server::Handle for TLS, awaiting ctrl_c (all
  platforms) and SIGTERM (unix).
- **Mutex poisoning panics (H-6)** — `.lock().expect("poisoned")`
  on the DecisionLog Mutex was a DoS amplifier: any panic in a
  holder crashed the next caller. Now uses
  `.unwrap_or_else(|e| e.into_inner())` (parking_lot code paths
  were already fine).
- **`/readyz` didn't actually verify dependencies (H-9)** — only
  checked `policies().count() > 0`. Now also checks audit log
  was opened and returns 503 otherwise.
- **`metrics::Counter::inc()` returned 0 forever (H-7)** — the impl
  had a comment "// placeholder, real impl below" and returned 0
  without incrementing. Now deprecated with a snapshot-only API;
  new code should use `AtomicCounter`.
- **Argon2id params below OWASP 2024 (H-11)** — 19 MiB / t=2 / p=1
  bumped to 64 MiB / t=3 / p=4. Verify cost goes from ~30 ms to
  ~150 ms, appropriate for an auth boundary.
- **`blast_radius::analyze` leaked `/tmp` dirs forever (H-12)** —
  every call created `/tmp/agentguard-blast-…` and never cleaned
  up. Now uses `tempfile::tempdir()` for RAII cleanup.

#### Tests added

- `dpop::tests::valid_dpop_accepted`
- `dpop::tests::jkt_mismatch_rejected`
- `dpop::tests::signature_tamper_rejected`
- `dpop::tests::replay_rejected`
- `decision::log::tests::chain_id_persists_across_restart`
- `decision::log::tests::chained_append_advances_head`
- `commands::audit::tests::erase_preserves_chain_metadata`

Plus updated fixtures and callers for the new `verify(...,
expected_jkt)` signature.

#### Acknowledgements

Review performed by opencode against the v0.2.0 release candidate.
All findings rated CRITICAL or HIGH were addressed; rated MEDIUM
(init template is permissive by default, OTLP sink shutdown
ordering, missing `/metrics` route, two `cargo-deny advisories` for
transitive `rustls-pemfile` and `rustls-webpki`) are documented in
the existing "Known upstream advisories" section below.

## [0.2.0] - 2026-07-14

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

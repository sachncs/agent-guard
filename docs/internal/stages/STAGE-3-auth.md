# Stage 3 — Auth crate (JWT, OIDC, API keys, DPoP, SPIFFE)

**Goal:** Real authentication. The PDP stops trusting unverified callers.

**Pre-flight:** Stage 2 complete. Hash-chained audit log works.

## Todos

### 3.1 — Crate setup
- [ ] `crates/agentguard-auth/Cargo.toml`:
  - Dependencies: `serde`, `serde_json`, `async-trait`, `tokio`, `reqwest`, `chrono`, `uuid`, `thiserror`, `parking_lot`, `tracing`
  - Optional (feature-gated):
    - `feature = "jwt"`: `jsonwebtoken`, `openidconnect`
    - `feature = "dpop"`: `jsonwebtoken`, `rsa` (for RS256 verification)
    - `feature = "spiffe"`: `rust-spiffe`
    - `feature = "api-keys"`: `argon2`, `rand`
  - Default features: `["jwt", "api-keys"]` (most common)
- [ ] `src/lib.rs`: gate modules behind features

### 3.2 — Errors
- [ ] `src/error.rs` with `AuthError` enum covering all failure modes:
  - `JwtInvalid(reason)`, `JwtExpired`, `JwtAudienceMismatch`, `JwtIssuerMismatch`, `JwtUnknownKid`
  - `OidcDiscovery(reason)`, `JwksFetch(reason)`
  - `DpopInvalid(reason)`, `DpopMismatch { expected: String, actual: String }`, `DpopReplay`
  - `SpiffeFetch(reason)`, `SpiffeExpired`
  - `ApiKeyInvalid`, `ApiKeyExpired`, `ApiKeyRevoked`
  - `Clock`, `Other(String)`

### 3.3 — Key registry (JWKS-style)
- [ ] `src/key_registry.rs`:
  - `pub struct KeyRegistry { keys: RwLock<HashMap<Kid, KeyEntry>> }`
  - `KeyEntry { alg: Algorithm, key: KeyMaterial, grace_expires_at: Option<Instant> }`
  - `KeyMaterial::Hmac(Vec<u8>)`, `KeyMaterial::Rsa(RSAPublicKey)`, `KeyMaterial::Ecdsa(ECPublicKey)`, `KeyMaterial::Ed25519(VerifyingKey)`
  - `add(kid, key)` registers a key
  - `rotate(kid, new_key)` registers a new key with the same kid; old key gets a grace period (default 7 days)
  - `get(kid) -> Option<&KeyEntry>` returns the active key
  - `get_for_verification(kid) -> Vec<&KeyEntry>` returns all valid keys for the kid (handles rotation grace)
  - Test: `key_registry_rotates_with_grace`

### 3.4 — JWT validation (feature `jwt`)
- [ ] `src/jwt.rs`:
  - `pub struct JwtConfig { issuer: String, audience: String, algorithms: Vec<Algorithm>, jwks_uri: Option<String>, clock_skew: Duration }`
  - `pub struct JwtValidator { config: JwtConfig, keys: KeyRegistry, http: reqwest::Client }`
  - `JwtValidator::new(config) -> Result<Self>`
  - `pub async fn validate(&self, token: &str) -> Result<ValidatedJwt, AuthError>`:
    - Decode header → get `kid` + `alg`
    - Reject if `alg` not in `algorithms` whitelist (RFC 8725 §3.1)
    - Look up key by `kid`
    - Verify signature with `jsonwebtoken::decode`
    - Validate `iss` matches `config.issuer`
    - Validate `aud` matches `config.audience`
    - Validate `exp`/`nbf` with `clock_skew` tolerance
    - Return `ValidatedJwt { claims, header }`
  - `pub async fn refresh_jwks(&self) -> Result<(), AuthError>` — fetch from `jwks_uri`, populate KeyRegistry
  - Background task: `pub fn spawn_jwks_refresher(self: Arc<Self>, interval: Duration)` — periodic refresh
  - Test: `jwt_validator_rejects_expired`, `jwt_validator_rejects_wrong_audience`, `jwt_validator_accepts_with_grace_period`

### 3.5 — OIDC discovery (feature `jwt`)
- [ ] `src/oidc.rs`:
  - `pub struct OidcConfig { issuer: String, audience: String, algorithms: Vec<Algorithm> }`
  - `pub async fn discover(config: OidcConfig) -> Result<(JwtValidator, OidcMetadata), AuthError>`:
    - GET `/.well-known/openid-configuration` (RFC 8414)
    - Parse `jwks_uri`
    - Fetch JWKS and populate registry
    - Return validator + metadata (for logging/debugging)
  - `pub struct OidcMetadata { issuer: String, authorization_endpoint: String, jwks_uri: String, ... }` — typed subset
  - Test: `oidc_discovery_resolves_jwks` (mock HTTP server with `wiremock`)

### 3.6 — API keys (feature `api-keys`)
- [ ] `src/api_key.rs`:
  - `pub struct ApiKey { id: String, prefix: String, secret_hash: String, scopes: Vec<String>, created_at: Timestamp, expires_at: Option<Timestamp>, last_used_at: Option<Timestamp>, revoked_at: Option<Timestamp> }`
  - Key format: `<prefix>_<id>_<secret>` where `secret` is 32 bytes base64url, `secret_hash` is Argon2id(password, secret)
  - `pub struct ApiKeyStore { keys: RwLock<Vec<ApiKey>> }`
  - `load_from_file(path) -> Result<Self>` — reads JSON file
  - `save_to_file(&self, path) -> Result<()>` — writes JSON file
  - `create(prefix, scopes, ttl) -> (ApiKey, String)` — generates key + secret, returns pair
  - `verify(raw_key) -> Result<&ApiKey, AuthError>` — extracts id, looks up, Argon2-verifies hash
  - `revoke(id) -> Result<()>` — sets revoked_at
  - `rotate(id) -> Result<(ApiKey, String)>` — creates new secret, marks old as grace-period (optional in v2.0)
  - Test: `api_key_create_and_verify`, `api_key_revoke_blocks_verify`

### 3.7 — DPoP verification (feature `dpop`)
- [ ] `src/dpop.rs`:
  - `pub struct DpopVerifier { keys: KeyRegistry, allowed_htm: Vec<String>, clock_skew: Duration }`
  - `pub async fn verify(&self, dpop_header: &str, method: &str, uri: &str, access_token_hash: &[u8]) -> Result<DpopProof, AuthError>`:
    - Parse DPoP JWT from header
    - Verify signature against the JWK bound via `cnf.jkt` in the access token
    - Verify `htm` matches HTTP method
    - Verify `htu` matches request URI
    - Verify `ath` = SHA-256(access_token) (RFC 9449 §4.2)
    - Verify `iat` within clock_skew of now
    - Verify `jti` not in replay cache
    - Optionally verify `nonce` if the verifier was configured with one
  - `pub struct DpopProof { jti: String, jkt: String, iat: Timestamp, htm: String, htu: String }`
  - Replay cache: `crates/agentguard-auth/src/jti.rs`:
    - `pub struct JtiTracker { cache: parking_lot::Mutex<BloomFilter<[u8; 16]>>, ttl: Duration }`
    - `pub fn check_and_record(&self, jti: &[u8; 16]) -> Result<(), AuthError>` — returns DpopReplay if seen
    - Periodic eviction
  - Test: `dpop_verifier_accepts_valid_proof`, `dpop_verifier_rejects_replay`

### 3.8 — SPIFFE (feature `spiffe`)
- [ ] `src/spiffe.rs`:
  - `pub struct SpiffeValidator { workload_api: rust_spiffe::WorkloadApiClient, allowed_trust_domains: Vec<String>, clock_skew: Duration }`
  - `pub async fn fetch_svid(&self) -> Result<X509Svid, AuthError>`:
    - Calls SPIFFE Workload API to get the current X509-SVID
    - Validates it against allowed trust domains
    - Returns the SPIFFE ID (e.g. `spiffe://acme.com/agent/email-bot`)
  - `pub async fn verify_peer_cert(&self, cert_chain: &[Vec<u8>]) -> Result<String, AuthError>`:
    - Verifies the peer cert against SPIFFE root CAs
    - Extracts SPIFFE ID from URI SAN
  - Test: requires SPIRE running; provide integration test marked `#[ignore]` that connects to a mock Workload API
  - Unit test: SPIFFE ID parsing (`spiffe://trust.domain/path`)

### 3.9 — Authenticator façade
- [ ] `src/lib.rs`:
  ```rust
  pub struct Authenticator {
      jwt: Option<Arc<JwtValidator>>,
      api_keys: Option<Arc<ApiKeyStore>>,
      dpop: Option<Arc<DpopVerifier>>,
      spiffe: Option<Arc<SpiffeValidator>>,
  }
  impl Authenticator {
      pub fn builder() -> AuthenticatorBuilder;
      pub async fn authenticate(&self, req: &AuthRequest) -> Result<AuthenticatedPrincipal, AuthError>;
  }
  ```
- [ ] `AuthenticatedPrincipal { spiffe_id: Option<String>, subject: String, scopes: Vec<String>, jwt_claims: Option<serde_json::Value>, auth_method: AuthMethod }`
- [ ] `AuthMethod` enum: `Jwt`, `ApiKey`, `Spiffe`, `Anonymous` (for dev)
- [ ] `Authenticator::authenticate()`:
  - If `Authorization: Bearer <jwt>` → JWT
  - If `Authorization: Bearer <prefix>_<id>_<secret>` → API key (detect by prefix)
  - If `Authorization: DPoP <jwt>` + `DPoP: <proof>` → DPoP + JWT
  - If peer cert presented and Spiffe validator configured → SPIFFE
  - Test: `authenticator_routes_to_correct_validator`

### 3.10 — Wire into Authorizer
- [ ] `Authorizer::new()` accepts an optional `Arc<Authenticator>`
- [ ] `authorize()` optionally checks auth first
  - If auth enabled, `req.principal` must match the authenticated principal (or be implicit)
  - Else, deny with reason `"authentication required"`
- [ ] New constructor: `Authorizer::with_auth(store, auth) -> Result<Self>`

### 3.11 — CLI commands
- [ ] `agentguard auth introspect <token>` — RFC 7662 introspection (validates and prints claims)
- [ ] `agentguard auth revoke <jti>` — RFC 7009 revocation (locally only in v2)
- [ ] `agentguard keys create/list/revoke/rotate` — manage API keys
- [ ] `agentguard auth discover <issuer>` — OIDC discovery + print metadata

### 3.12 — Final verification
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes (8 core + ~3 chain + ~8 telemetry + ~10 auth = ~30+ tests)
- [ ] `cargo doc --workspace --no-deps` no warnings
- [ ] Manual smoke test: `agentguard auth introspect` with a test JWT

## Commit

```bash
git add -A
git commit -m "stage(3): auth crate — JWT, OIDC, API keys, DPoP, SPIFFE

- New crates/agentguard-auth crate (feature-gated: jwt, api-keys, dpop, spiffe)
- JwtValidator: RFC 8725 BCP, algorithm whitelist, kid-based key resolution, JWKS refresh
- OidcConfig::discover() fetches .well-known/openid-configuration + JWKS
- ApiKeyStore: Stripe-style prefix_id_secret format, Argon2id-hashed, create/list/rotate/revoke
- DpopVerifier: RFC 9449 proof-of-possession, htm/htu/ath/jti validation, replay protection
- SpiffeValidator: rust-spiffe Workload API client, trust-domain allowlist
- JtiTracker: Bloom-filter-backed replay cache with TTL eviction
- Authenticator façade: routes requests to the right validator based on Authorization header
- CLI: agentguard auth introspect/revoke/discover, agentguard keys {create,list,revoke,rotate}
- Authorizer::with_auth(store, auth) gates authorization on successful authentication"
```

## Done when
- [ ] Commit landed
- [ ] All auth tests pass (use wiremock for OIDC/JWKS fixtures; use RFC 9449 examples for DPoP)
- [ ] `cargo run --bin agentguard -- auth discover https://accounts.google.com` works
- [ ] Move to Stage 4

## What NOT to do
- Do not implement delegation v2 yet (Stage 4)
- Do not implement decision cache yet (Stage 5)
- Do not implement AuthZEN server yet (Stage 7)
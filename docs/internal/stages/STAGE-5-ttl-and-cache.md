# Stage 5 — TTL & decision cache

**Goal:** Decisions are cached with TTL, invalidated on policy change. Step-up
auth returns the right signals to the PEP.

**Pre-flight:** Stage 4 complete. Delegation v2 (JWS) works.

## Todos

### 5.1 — Decision cache implementation
- [ ] `crates/agentguard-core/src/decision/cache.rs`:
  ```rust
  pub struct DecisionCache {
      entries: parking_lot::Mutex<LruCache<CacheKey, CachedDecision>>,
      clock: Arc<dyn Clock>,
      default_ttl: Duration,
      deny_ttl: Duration,
      cache_denies: bool,
      policy_version: AtomicU64,
  }
  pub struct CacheKey([u8; 32]);  // SHA-256 of canonical request
  pub struct CachedDecision {
      effect: Effect,
      policies: Vec<String>,
      policy_effects: Vec<PolicyEffect>,
      reasons: Vec<String>,
      expires_at: Instant,
      policy_version_at_cache_time: u64,
  }
  ```
- [ ] `DecisionCache::new(capacity, clock, config) -> Self`
- [ ] `pub fn get(&self, key: &CacheKey) -> Option<CachedDecision>` — returns `None` if expired OR policy_version changed
- [ ] `pub fn put(&self, key: CacheKey, decision: Decision, ttl: Duration)`
- [ ] `pub fn invalidate_all(&self)` — bumps `policy_version` counter
- [ ] `pub fn stats(&self) -> CacheStats { hits, misses, evictions, size }`
- [ ] Use the `lru` crate
- [ ] Test: `cache_hits_within_ttl`, `cache_misses_after_ttl`, `cache_invalidates_on_policy_bump`

### 5.2 — Cache key derivation
- [ ] `CacheKey::for_request(req: &AgentRequest, schema_hash: [u8; 32]) -> Self`:
  - Hash canonical JSON of `{principal, action, resource, context.args, schema_hash}`
  - Excludes trace context, request_id, session.ip (to allow some variance)
  - Actually: include all fields for strict correctness; expose a `derive_with_session` flag for cases where you DO want per-IP caching
- [ ] Test: `cache_key_is_stable_across_request_ids`

### 5.3 — Authorizer integration
- [ ] `Authorizer` gains `cache: Arc<DecisionCache>` field (default: `DecisionCache::disabled()` — no caching)
- [ ] `Authorizer::with_cache(store, cache)` builder
- [ ] `authorize()`:
  - Compute cache key
  - If hit: return cached decision + emit `cache_hit` metric
  - If miss: evaluate, cache result with `default_ttl` (allow) or `deny_ttl` (deny)
- [ ] Decision record gains `cached: bool` field
- [ ] Test: `authorize_uses_cache_on_second_call`, `authorize_skips_cache_when_disabled`

### 5.4 — Schema-annotated TTLs
- [ ] Action schema can carry `cache_ttl: { default: Duration, max_sensitive: Duration, cache_denies: Bool }` annotations
- [ ] When evaluating, Authorizer reads the annotation from the schema and applies per-action
- [ ] Helper: `pub fn parse_duration(s: &str) -> Result<Duration, ...>` for schema source
- [ ] Add an example action to the starter schema showing this
- [ ] Test: `annotation_overrides_default_ttl`

### 5.5 — Step-up auth (real this time)
- [ ] Cedar policy with `context.session.amr contains "mfa"` predicate evaluates against `context.session.amr` (a list of strings)
- [ ] When the predicate fails, Authorizer returns:
  ```rust
  Decision {
      effect: Effect::Deny,
      reasons: vec!["step-up required".into()],
      required_step_up: Some(StepUp {
          acr_values: "urn:mace:in-common:iap:silver".into(),
          amr_values: "mfa hwk".into(),
      }),
  }
  ```
- [ ] New `StepUp` struct in `agentguard_core::decision`
- [ ] Decision record gains `step_up: Option<StepUp>` field
- [ ] Python SDK raises `StepUpRequired(step_up)` exception
- [ ] LangChain middleware surfaces `StepUpRequired` to the calling agent
- [ ] Test: `step_up_returned_when_mfa_missing_in_session`

### 5.6 — TTL helpers
- [ ] `crates/agentguard-core/src/ttl.rs` already has Clock + Timestamp; add:
  ```rust
  pub fn parse_duration(s: &str) -> Result<Duration, TtlError>;     // "30s", "5m", "2h", "1d"
  pub fn format_duration(d: Duration) -> String;                     // inverse
  ```
- [ ] CLI flags that take `--ttl` use these helpers
- [ ] Test: `parse_duration_handles_all_units`

### 5.7 — Wire cache into CLI
- [ ] `agentguard authorize --no-cache` to skip the cache for one call
- [ ] `agentguard cache stats` — print `hits, misses, size, evictions`
- [ ] `agentguard cache invalidate` — manually flush
- [ ] Test: CLI smoke test — two `authorize` calls, second is a cache hit (logged as such)

### 5.8 — Optional Redis backend (P1, not blocker)
- [ ] Trait `pub trait CacheBackend: Send + Sync { async fn get(&self, key: &[u8]) -> Option<Vec<u8>>; async fn put(&self, key: &[u8], value: Vec<u8>, ttl: Duration); }`
- [ ] `RedisCacheBackend` behind feature flag
- [ ] `LruCacheBackend` (default, in-process)
- [ ] `MultiTierCache { l1: LruCacheBackend, l2: Option<Arc<dyn CacheBackend>> }`
- [ ] Test: with feature on, integration test against `redis::Client::open("redis://localhost")` (marked `#[ignore]`)

### 5.9 — Final verification
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo doc --workspace --no-deps` no warnings
- [ ] `agentguard cache stats` works after several `authorize` calls
- [ ] Step-up auth raises the right signal in LangChain middleware

## Commit

```bash
git add -A
git commit -m "stage(5): decision cache with TTL + step-up auth

- DecisionCache (LRU, in-process): keyed by SHA-256 of canonical request
- TTL strategies: default_ttl for allow, deny_ttl for deny, optional cache_denies
- Schema-annotated per-action TTLs (cache_ttl.default, cache_ttl.max_sensitive)
- Policy-version invalidation: cache bumped atomically on policy reload
- Cache stats: hits, misses, evictions, size
- StepUp struct in Decision: acr_values + amr_values per RFC 9470
- Python SDK raises StepUpRequired exception
- LangChain middleware surfaces StepUpRequired to calling agent
- CLI: --no-cache flag, agentguard cache {stats, invalidate}
- Optional Redis backend behind feature flag"
```

## Done when
- [ ] Commit landed
- [ ] All cache tests pass
- [ ] Step-up flows end-to-end (Cedar policy → Decision → Python exception → LangChain callback)
- [ ] Move to Stage 6

## What NOT to do
- Do not implement policy versioning or hot reload yet (Stage 6)
- Do not implement AuthZEN server yet (Stage 7)
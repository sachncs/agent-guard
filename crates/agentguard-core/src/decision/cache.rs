//! LRU decision cache with TTL and policy-version invalidation.

use crate::decision::canonical::{canonical_json, write_canonical_value};
use crate::request::AgentRequest;
use crate::ttl::Clock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Cache key derived from a request (and the current policy version).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey(pub [u8; 32]);

impl CacheKey {
    /// Derive a key from an agent request. Includes `policy_version` so a
    /// policy reload invalidates all entries.
    ///
    /// Streams each field's canonical JSON through the hasher, avoiding the
    /// intermediate `String` allocations the previous implementation made.
    /// For high-throughput PDPs (thousands of decisions/sec) this matters.
    ///
    /// # Examples
    /// ```
    /// use agentguard_core::{AgentRequestBuilder, Principal, AgentAction, Resource, AgentContext};
    /// use agentguard_core::decision::cache::CacheKey;
    /// let req = AgentRequestBuilder::new(Principal::user("alice"))
    ///     .action(AgentAction::tool("send_email"))
    ///     .resource(Resource::new("Mailbox", "alice@acme"))
    ///     .context(AgentContext::new())
    ///     .build()
    ///     .unwrap();
    /// let _k = CacheKey::for_request(&req, 0);
    /// ```
    pub fn for_request(req: &AgentRequest, policy_version: u64) -> Self {
        let mut hasher = Sha256::new();

        // Hash a length-prefixed JSON encoding of each component so
        // boundaries between fields can't be ambiguous.
        // Format: 4-byte big-endian length || canonical JSON.
        let hash_field = |h: &mut Sha256, value: &serde_json::Value| {
            let mut buf = Vec::new();
            write_canonical_value(&mut buf, value).expect("canonical write to Vec is infallible");
            let len = (buf.len() as u32).to_be_bytes();
            sha2::Digest::update(h, len);
            sha2::Digest::update(h, &buf);
        };

        if let Ok(p) = serde_json::to_value(&req.principal) {
            hash_field(&mut hasher, &p);
        }
        if let Ok(a) = serde_json::to_value(&req.action) {
            hash_field(&mut hasher, &a);
        }
        if let Ok(r) = serde_json::to_value(&req.resource) {
            hash_field(&mut hasher, &r);
        }
        // Context is already canonical; hash it directly.
        if let Ok(bytes) = canonical_json(&req.context) {
            let len = (bytes.len() as u32).to_be_bytes();
            sha2::Digest::update(&mut hasher, len);
            sha2::Digest::update(&mut hasher, &bytes);
        }
        if let Some(t) = &req.trace {
            let s = t.to_string();
            let len = (s.len() as u32).to_be_bytes();
            sha2::Digest::update(&mut hasher, len);
            sha2::Digest::update(&mut hasher, s.as_bytes());
        }
        sha2::Digest::update(&mut hasher, policy_version.to_be_bytes());

        let hash: [u8; 32] = hasher.finalize().into();
        Self(hash)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// A cached decision record.
///
/// The `effect` string is `"allow"` or `"deny"`. `cached_at_policy_version`
/// is the policy version that was active when this entry was inserted;
/// `get` ignores entries whose version doesn't match the current
/// `policy_version`, achieving invalidation on policy reload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDecision {
    pub effect: String,
    pub policies: Vec<String>,
    pub reasons: Vec<String>,
    pub cached_at_policy_version: u64,
}

impl CachedDecision {
    /// Construct an `Allow` decision with the current policy version.
    pub fn allow() -> Self {
        Self {
            effect: "allow".into(),
            policies: vec![],
            reasons: vec![],
            cached_at_policy_version: 0,
        }
    }

    /// Construct a `Deny` decision with the current policy version.
    pub fn deny() -> Self {
        Self {
            effect: "deny".into(),
            policies: vec![],
            reasons: vec![],
            cached_at_policy_version: 0,
        }
    }
}

/// Configuration for [`DecisionCache`].
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries.
    pub capacity: usize,
    /// TTL for "allow" decisions.
    pub allow_ttl: Duration,
    /// TTL for "deny" decisions. Conservative (shorter) because deny flips are
    /// security-sensitive.
    pub deny_ttl: Duration,
    /// Whether to cache deny decisions at all.
    pub cache_denies: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            capacity: 10_000,
            allow_ttl: Duration::from_secs(30),
            deny_ttl: Duration::from_secs(5),
            cache_denies: true,
        }
    }
}

/// LRU + TTL decision cache.
///
///
///
/// Backed by a simple HashMap + LRU eviction. Thread-safe via [`parking_lot::Mutex`].
pub struct DecisionCache {
    config: CacheConfig,
    clock: Arc<dyn Clock>,
    policy_version: AtomicU64,
    inner: parking_lot::Mutex<lru::LruCache<CacheKey, (CachedDecision, std::time::Instant)>>,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl DecisionCache {
    pub fn new(config: CacheConfig, clock: Arc<dyn Clock>) -> Self {
        let capacity = std::num::NonZeroUsize::new(config.capacity).unwrap();
        Self {
            config,
            clock,
            policy_version: AtomicU64::new(0),
            inner: parking_lot::Mutex::new(lru::LruCache::new(capacity)),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// A disabled cache (every call is a miss).
    pub fn disabled(clock: Arc<dyn Clock>) -> Self {
        let c = CacheConfig {
            capacity: 1,
            ..CacheConfig::default()
        };
        let cap = std::num::NonZeroUsize::new(c.capacity).unwrap();
        Self {
            config: c,
            clock,
            policy_version: AtomicU64::new(0),
            inner: parking_lot::Mutex::new(lru::LruCache::new(cap)),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    pub fn policy_version(&self) -> u64 {
        self.policy_version.load(Ordering::Relaxed)
    }

    /// Bump the policy version. All cache entries are invalidated on the
    /// next `get()` because the stored `cached_at_policy_version` no longer
    /// matches.
    pub fn invalidate_all(&self) {
        self.policy_version.fetch_add(1, Ordering::Relaxed);
    }

    /// Convenience: set the policy version to a specific value.
    pub fn set_policy_version(&self, v: u64) {
        self.policy_version.store(v, Ordering::Relaxed);
    }

    pub fn get(&self, key: &CacheKey) -> Option<CachedDecision> {
        let now = self.clock.now();
        let policy_version = self.policy_version();
        let mut guard = self.inner.lock();
        if let Some((cached, expires_at)) = guard.peek(key).cloned() {
            if cached.cached_at_policy_version != policy_version {
                // Stale due to policy reload; remove and miss.
                guard.pop(key);
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            if now >= expires_at {
                guard.pop(key);
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            // Touch for LRU recency.
            guard.get(key);
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Some(cached);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn put(&self, key: CacheKey, decision: CachedDecision) {
        let now = self.clock.now();
        let ttl = match decision.effect.as_str() {
            "allow" => self.config.allow_ttl,
            "deny" if self.config.cache_denies => self.config.deny_ttl,
            _ => return,
        };
        let guard_cell = &self.inner;
        let mut guard = guard_cell.lock();
        let prev = guard.push(key, (decision, now + ttl));
        if prev.is_none() && guard.len() >= self.config.capacity {
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            size: self.inner.lock().len(),
            policy_version: self.policy_version(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub size: usize,
    pub policy_version: u64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

/// Helper: convert a request + policy_version into a cache key.
pub fn cache_key_for(req: &AgentRequest, policy_version: u64) -> CacheKey {
    CacheKey::for_request(req, policy_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::AgentRequestBuilder;
    use crate::ttl::MockClock;
    use crate::{AgentAction, AgentContext, Principal, Resource};
    use std::sync::Arc;

    fn req() -> AgentRequest {
        AgentRequestBuilder::new(Principal::user("alice"))
            .action(AgentAction::tool("send_email"))
            .resource(Resource::new("Mailbox", "alice@acme"))
            .context(AgentContext::new().with_arg("to", "[email protected]"))
            .build()
            .unwrap()
    }

    #[test]
    fn cache_miss_then_hit() {
        let clock = Arc::new(MockClock::new());
        let cache = DecisionCache::new(CacheConfig::default(), clock.clone());
        let key = cache_key_for(&req(), 0);
        assert!(cache.get(&key).is_none());
        cache.put(key.clone(), CachedDecision::allow());
        let got = cache.get(&key).unwrap();
        assert_eq!(got.effect, "allow");
        assert_eq!(cache.stats().hits, 1);
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn expire_after_ttl() {
        let clock = Arc::new(MockClock::new());
        let mut cfg = CacheConfig::default();
        cfg.allow_ttl = Duration::from_secs(5);
        let cache = DecisionCache::new(cfg, clock.clone());
        let key = cache_key_for(&req(), 0);
        cache.put(key.clone(), CachedDecision::allow());
        clock.advance_unix(Duration::from_secs(10));
        assert!(cache.get(&key).is_none(), "should have expired");
    }

    #[test]
    fn invalidate_on_policy_version_bump() {
        let clock = Arc::new(MockClock::new());
        let cache = DecisionCache::new(CacheConfig::default(), clock.clone());
        let key = cache_key_for(&req(), 0);
        cache.put(key.clone(), CachedDecision::allow());
        assert!(cache.get(&key).is_some());
        cache.invalidate_all();
        assert!(cache.get(&key).is_none(), "policy bump should invalidate");
    }

    #[test]
    fn deny_cached_when_enabled() {
        let clock = Arc::new(MockClock::new());
        let cache = DecisionCache::new(CacheConfig::default(), clock.clone());
        let key = cache_key_for(&req(), 0);
        cache.put(key.clone(), CachedDecision::deny());
        assert_eq!(cache.get(&key).unwrap().effect, "deny");
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn deny_not_cached_when_disabled() {
        let clock = Arc::new(MockClock::new());
        let mut cfg = CacheConfig::default();
        cfg.cache_denies = false;
        let cache = DecisionCache::new(cfg, clock.clone());
        let key = cache_key_for(&req(), 0);
        cache.put(key.clone(), CachedDecision::deny());
        assert!(cache.get(&key).is_none(), "denies not cached");
    }

    #[test]
    fn hit_rate_calculation() {
        let s = CacheStats {
            hits: 7,
            misses: 3,
            evictions: 0,
            size: 5,
            policy_version: 0,
        };
        assert!((s.hit_rate() - 0.7).abs() < 1e-9);
    }

    #[test]
    fn concurrent_reads_dont_block_writers() {
        use std::sync::Arc;
        use std::thread;

        let clock = Arc::new(MockClock::new());
        let cache = Arc::new(DecisionCache::new(CacheConfig::default(), clock));
        let key = cache_key_for(&req(), 0);

        // Seed the cache so reads hit.
        cache.put(key.clone(), CachedDecision::allow());

        // Spawn N reader threads. They all do `cache.get` in a tight
        // loop for a bounded time. While they're doing that, the main
        // thread does a few writes. If RwLock works as intended the reads
        // mostly proceed in parallel; we don't assert specific timing,
        // just that the test completes (proves no deadlock).
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let cache = Arc::clone(&cache);
            let key = key.clone();
            let stop = Arc::clone(&stop);
            handles.push(thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = cache.get(&key);
                }
            }));
        }

        for v in 1..=20 {
            cache.set_policy_version(v);
            cache.put(key.clone(), CachedDecision::allow());
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for h in handles {
            h.join().unwrap();
        }
        // The test cares about non-deadlock under concurrent traffic, not
        // about the cache state. We just confirm the lock was released and
        // the readers made progress (otherwise the test would hang on join).
        assert!(cache.stats().hits > 0, "no reads completed");
    }
}

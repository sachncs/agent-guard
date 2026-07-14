//! Decision cache: LRU + TTL, with policy-version invalidation.
//!
//! Stub for v2.0.0 — the implementation lives in Stage 5.

use std::time::Duration;

/// LRU + TTL cache for authorization decisions.
///
/// Decisions are keyed by a hash of the request's principal/action/resource/
/// context + the current policy version. Cache entries are invalidated
/// when the policy version bumps.
///
/// Default capacities and TTLs:
/// - capacity: 10_000 entries
/// - allow TTL: 30 seconds
/// - deny TTL: 5 seconds (conservative — deny decisions are sensitive)
pub struct DecisionCache {
    _phantom: std::marker::PhantomData<()>,
}

impl DecisionCache {
    /// Construct a cache with default capacity and TTLs.
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Construct a cache with a custom allow TTL.
    pub fn with_allow_ttl(_ttl: Duration) -> Self {
        Self::new()
    }

    /// Construct a disabled cache (every request is evaluated).
    pub fn disabled() -> Self {
        Self::new()
    }
}

impl Default for DecisionCache {
    fn default() -> Self {
        Self::new()
    }
}

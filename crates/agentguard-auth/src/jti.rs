//! jti tracker for replay protection.
//!
//! Bucket-based: jtis are partitioned into time buckets of width
//! `ttl / N_BUCKETS`. On each `check_and_record` call the bucket
//! index for `now` is computed and the previous bucket is dropped
//! wholesale — a single `HashMap::clear()` replaces the previous
//! O(N) `HashMap::retain`. Memory is bounded by the number of
//! distinct jtis arriving within the TTL window; lookup is O(1)
//! per request.
//!
//! For deployments with very high `jti` cardinality, replace the
//! inner `HashMap` with a probabilistic structure (e.g. cuckoo
//! filter).

use crate::error::Result;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Number of time buckets per TTL window. Each bucket covers
/// `ttl / N_BUCKETS`; on rotation we drop the oldest bucket.
const N_BUCKETS: usize = 4;

/// In-memory tracker of seen `jti` values.
pub struct JtiTracker {
    /// One `HashMap` per bucket. Old buckets are cleared in O(1).
    buckets: [Mutex<HashMap<[u8; 16], ()>>; N_BUCKETS],
    /// TTL per jti entry.
    ttl: Duration,
    /// Last rotation timestamp (used to compute bucket index).
    last_rotation: Mutex<Instant>,
    /// Tracked jti count across all buckets (cached).
    count: Mutex<usize>,
    /// Maximum entries per bucket before forced rotation.
    per_bucket_cap: usize,
}

impl JtiTracker {
    pub fn new(ttl: Duration) -> Self {
        // Cap per bucket: ttl is the upper bound on lifetime; bound the
        // high-cardinality attack surface by capping bucket size.
        // 65k entries × 16 bytes = ~1 MiB per bucket; well under any
        // reasonable memory budget.
        const DEFAULT_PER_BUCKET_CAP: usize = 65_536;
        Self {
            buckets: std::array::from_fn(|_| Mutex::new(HashMap::new())),
            ttl,
            last_rotation: Mutex::new(Instant::now()),
            count: Mutex::new(0),
            per_bucket_cap: DEFAULT_PER_BUCKET_CAP,
        }
    }

    /// Compute the bucket index for `now`. Updates the rotation
    /// timestamp and drops the oldest bucket when `now` crosses
    /// into a new bucket window.
    fn current_bucket(&self, now: Instant) -> usize {
        let mut last = self.last_rotation.lock();
        let elapsed = now.duration_since(*last);
        let bucket_width = self.ttl / N_BUCKETS as u32;
        if elapsed >= bucket_width {
            // Rotate: drop the bucket we're about to overwrite, plus
            // any stale ones since last rotation.
            let steps = (elapsed.as_nanos() / bucket_width.as_nanos().max(1)) as usize;
            let drop_count = steps.min(N_BUCKETS);
            let cur_idx = ((now.duration_since(*last).as_nanos() / bucket_width.as_nanos().max(1))
                as usize)
                % N_BUCKETS;
            for i in 0..drop_count {
                let idx = (cur_idx + N_BUCKETS - i) % N_BUCKETS;
                let mut g = self.buckets[idx].lock();
                *self.count.lock() -= g.len();
                g.clear();
            }
            *last = now;
        }
        let step = (now.duration_since(*last).as_nanos() / bucket_width.as_nanos().max(1)) as usize;
        step % N_BUCKETS
    }

    /// Record `jti`. Returns Ok if not seen before, Err if it's a replay.
    pub fn check_and_record(&self, jti: &[u8; 16]) -> Result<()> {
        let now = Instant::now();
        let idx = self.current_bucket(now);
        let mut guard = self.buckets[idx].lock();
        // Forced rotation when a bucket fills up.
        if guard.len() >= self.per_bucket_cap {
            drop(guard);
            // Force a full rotation: clear all buckets.
            self.force_rotate(now);
            let idx = self.current_bucket(now);
            guard = self.buckets[idx].lock();
        }
        if guard.contains_key(jti) {
            return Err(crate::error::AuthError::DpopReplay(hex::encode(jti)));
        }
        guard.insert(*jti, ());
        *self.count.lock() += 1;
        Ok(())
    }

    fn force_rotate(&self, now: Instant) {
        let mut last = self.last_rotation.lock();
        for b in &self.buckets {
            let mut g = b.lock();
            *self.count.lock() -= g.len();
            g.clear();
        }
        *last = now;
    }

    pub fn len(&self) -> usize {
        *self.count.lock()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthError;

    #[test]
    fn first_occurrence_ok_replay_blocked() {
        let t = JtiTracker::new(Duration::from_secs(60));
        let jti = [1u8; 16];
        t.check_and_record(&jti).unwrap();
        assert!(t.check_and_record(&jti).is_err());
    }

    #[test]
    fn distinct_jtis_accepted() {
        let t = JtiTracker::new(Duration::from_secs(60));
        t.check_and_record(&[1u8; 16]).unwrap();
        t.check_and_record(&[2u8; 16]).unwrap();
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn expired_entries_are_reaped() {
        // Use a 0-second TTL so any entry expires immediately.
        let t = JtiTracker::new(Duration::from_secs(0));
        t.check_and_record(&[1u8; 16]).unwrap();
        // Sleep briefly so the entry is "old enough" to expire.
        std::thread::sleep(Duration::from_millis(10));
        // The reaping is opportunistic — call check_and_record on a new jti,
        // which triggers retain() that drops expired entries.
        t.check_and_record(&[2u8; 16]).unwrap();
        // Old entry should have been reaped.
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn new_is_empty() {
        let t = JtiTracker::new(Duration::from_secs(60));
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn replay_blocked_returns_descriptive_error() {
        // The error must include the offending jti (hex-encoded) so the
        // operator can identify the duplicate in their logs.
        let t = JtiTracker::new(Duration::from_secs(60));
        let jti = [0xab; 16];
        t.check_and_record(&jti).unwrap();
        let err = t.check_and_record(&jti).unwrap_err();
        match err {
            AuthError::DpopReplay(s) => {
                assert!(s.contains("abababababababab"), "got: {}", s);
            }
            other => panic!("expected DpopReplay, got: {:?}", other),
        }
    }
}

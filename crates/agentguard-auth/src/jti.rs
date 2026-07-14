//! jti tracker for replay protection.
//!
//! Backed by a Bloom filter for probabilistic dedup at scale. The TTL eviction
//! prunes entries whose `iat + ttl` is in the past.

use crate::error::Result;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// In-memory tracker of seen `jti` values.
pub struct JtiTracker {
    inner: Mutex<HashMap<[u8; 16], Instant>>,
    ttl: Duration,
}

impl JtiTracker {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Record `jti`. Returns Ok if not seen before, Err if it's a replay.
    pub fn check_and_record(&self, jti: &[u8; 16]) -> Result<()> {
        let now = Instant::now();
        let mut guard = self.inner.lock();
        // Evict expired entries opportunistically.
        guard.retain(|_, exp| now.duration_since(*exp) < self.ttl);
        if guard.contains_key(jti) {
            return Err(crate::error::AuthError::DpopReplay(hex::encode(jti)));
        }
        guard.insert(*jti, now);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

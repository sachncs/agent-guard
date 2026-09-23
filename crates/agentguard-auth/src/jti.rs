//! jti tracker for replay protection.
//!
//! Seen JTIs are stored with monotonic timestamps. Expired entries are
//! periodically reaped, while duplicate lookups and insertions stay atomic
//! under one mutex. A hard capacity bounds memory; when full, new proofs are
//! rejected instead of discarding live replay history.

use crate::error::Result;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum number of live proof identifiers retained by one tracker.
const DEFAULT_MAX_ENTRIES: usize = 262_144;
/// Opportunistic expiry sweep interval as a fraction of the replay TTL.
const SWEEP_DIVISOR: u32 = 4;

struct JtiState {
    seen: HashMap<[u8; 16], Instant>,
    last_sweep: Instant,
}

/// In-memory tracker of seen `jti` values.
pub struct JtiTracker {
    state: Mutex<JtiState>,
    ttl: Duration,
    max_entries: usize,
    sweep_interval: Duration,
}

impl JtiTracker {
    pub fn new(ttl: Duration) -> Self {
        Self::build(ttl, DEFAULT_MAX_ENTRIES)
    }

    /// Construct a tracker with an explicit live-entry limit.
    ///
    /// The default [`Self::new`] limit is 262,144 identifiers. Capacity
    /// exhaustion rejects new proofs; it never evicts unexpired replay state.
    pub fn with_capacity(ttl: Duration, max_entries: usize) -> Result<Self> {
        if max_entries == 0 {
            return Err(crate::error::AuthError::DpopInvalid(
                "JTI tracker capacity must be positive".into(),
            ));
        }
        Ok(Self::build(ttl, max_entries))
    }

    fn build(ttl: Duration, max_entries: usize) -> Self {
        let now = Instant::now();
        Self {
            state: Mutex::new(JtiState {
                seen: HashMap::new(),
                last_sweep: now,
            }),
            ttl,
            max_entries,
            sweep_interval: ttl / SWEEP_DIVISOR,
        }
    }

    /// Record `jti`. Returns an error for replays or when capacity is exhausted.
    pub fn check_and_record(&self, jti: &[u8; 16]) -> Result<()> {
        let now = Instant::now();
        let mut state = self.state.lock();

        if state
            .seen
            .get(jti)
            .is_some_and(|seen_at| now.duration_since(*seen_at) < self.ttl)
        {
            return Err(crate::error::AuthError::DpopReplay(hex::encode(jti)));
        }
        state.seen.remove(jti);

        if now.duration_since(state.last_sweep) >= self.sweep_interval {
            state
                .seen
                .retain(|_, seen_at| now.duration_since(*seen_at) < self.ttl);
            state.last_sweep = now;
        }

        if state.seen.len() >= self.max_entries {
            return Err(crate::error::AuthError::DpopCapacityExceeded);
        }

        state.seen.insert(*jti, now);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.state.lock().seen.len()
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
        // The reaping is opportunistic — a new identifier triggers a sweep.
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

    #[test]
    fn capacity_exhaustion_does_not_discard_live_replay_history() {
        let tracker = JtiTracker::with_capacity(Duration::from_secs(60), 2).unwrap();
        let first = [1u8; 16];
        tracker.check_and_record(&first).unwrap();
        tracker.check_and_record(&[2u8; 16]).unwrap();

        assert!(matches!(
            tracker.check_and_record(&[3u8; 16]),
            Err(AuthError::DpopCapacityExceeded)
        ));
        assert!(matches!(
            tracker.check_and_record(&first),
            Err(AuthError::DpopReplay(_))
        ));
        assert_eq!(tracker.len(), 2);
    }

    #[test]
    fn expired_entries_are_reclaimed_before_capacity_rejection() {
        let tracker = JtiTracker::with_capacity(Duration::from_millis(20), 1).unwrap();
        tracker.check_and_record(&[1u8; 16]).unwrap();
        std::thread::sleep(Duration::from_millis(25));

        tracker.check_and_record(&[2u8; 16]).unwrap();
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn explicit_capacity_must_be_positive() {
        assert!(matches!(
            JtiTracker::with_capacity(Duration::from_secs(60), 0),
            Err(AuthError::DpopInvalid(_))
        ));
    }

    #[test]
    fn concurrent_replays_are_recorded_atomically() {
        let tracker = std::sync::Arc::new(JtiTracker::new(Duration::from_secs(60)));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let threads = (0..16)
            .map(|_| {
                let tracker = std::sync::Arc::clone(&tracker);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    tracker.check_and_record(&[42u8; 16]).is_ok()
                })
            })
            .collect::<Vec<_>>();
        let accepted = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|accepted| *accepted)
            .count();

        assert_eq!(accepted, 1);
        assert_eq!(tracker.len(), 1);
    }
}

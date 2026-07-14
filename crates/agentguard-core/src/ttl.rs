//! Time-related primitives: [`Clock`] trait, [`Timestamp`] type, and Duration parsing.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Error from [`parse_duration`].
#[derive(Debug, thiserror::Error)]
#[error("invalid duration: {0}")]
pub struct TtlParseError(String);

/// Unix-epoch seconds. Newtype to avoid mixing with other integers.
pub type Timestamp = i64;

/// A pluggable time source.
///
/// Used by the authorizer, cache, and delegation verifier so that tests can
/// use a [`MockClock`] to drive deterministic TTL behavior.
pub trait Clock: Send + Sync {
    /// Monotonic instant (for measuring elapsed time).
    fn now(&self) -> Instant;

    /// Wall-clock unix seconds (for absolute-time checks like `exp`).
    fn unix_now(&self) -> Timestamp;
}

/// Production clock backed by the OS.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn unix_now(&self) -> Timestamp {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as Timestamp)
            .unwrap_or(0)
    }
}

/// Test clock — advanceable by the test.
#[derive(Debug)]
pub struct MockClock {
    inner: parking_lot::Mutex<Instant>,
    unix_inner: parking_lot::Mutex<Timestamp>,
}

impl MockClock {
    pub fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(Instant::now()),
            unix_inner: parking_lot::Mutex::new(0),
        }
    }

    /// Set the wall-clock time to the given unix seconds.
    pub fn set_unix(&self, t: Timestamp) {
        *self.unix_inner.lock() = t;
    }

    /// Advance the wall clock by `d`. Also advances the monotonic clock so
    /// `Duration`-based TTLs work in tests.
    pub fn advance_unix(&self, d: Duration) {
        *self.unix_inner.lock() += d.as_secs() as Timestamp;
        let now = *self.inner.lock();
        *self.inner.lock() = now.checked_add(d).unwrap_or(now);
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MockClock {
    fn now(&self) -> Instant {
        *self.inner.lock()
    }

    fn unix_now(&self) -> Timestamp {
        *self.unix_inner.lock()
    }
}

/// Parse a humantime string into a `Duration`.
///
/// Accepts forms like `30s`, `5m`, `2h`, `1d`, or just a number of seconds.
/// Returns an error if the string is malformed.
pub fn parse_duration(s: &str) -> std::result::Result<Duration, TtlParseError> {
    use std::str::FromStr;
    humantime::Duration::from_str(s)
        .map(Into::into)
        .map_err(|e| TtlParseError(e.to_string()))
}

/// Format a `Duration` as a humantime string (e.g. `5m`, `2h`).
pub fn format_duration(d: Duration) -> String {
    humantime::format_duration(d).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_returns_sane_unix_now() {
        let c = SystemClock;
        let t = c.unix_now();
        // After Jan 2020, unix seconds should be > 1.5e9.
        assert!(t > 1_500_000_000, "unix_now returned {}", t);
    }

    #[test]
    fn mock_clock_advances() {
        let c = MockClock::new();
        c.set_unix(100);
        assert_eq!(c.unix_now(), 100);
        c.advance_unix(Duration::from_secs(60));
        assert_eq!(c.unix_now(), 160);
    }

    #[test]
    fn parse_and_format_roundtrip() {
        let cases = ["30s", "5m", "2h", "1d"];
        for s in cases {
            let d = parse_duration(s).unwrap();
            assert!(format_duration(d).contains(|c: char| c.is_ascii_digit()));
        }
    }
}

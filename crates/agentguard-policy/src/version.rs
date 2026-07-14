//! Policy version identifiers.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A monotonic policy version for a single tenant.
///
/// Versions are simple `u64` counters. Monotonicity is the caller's
/// responsibility — [`super::BundleRegistry::register`] does not check
/// that a new version is strictly greater than the previous one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyVersion(u64);

impl PolicyVersion {
    pub fn new(v: u64) -> Self {
        Self(v)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns the next version (v + 1). Saturates at `u64::MAX`.
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

impl fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering() {
        assert!(PolicyVersion::new(2) > PolicyVersion::new(1));
        assert_eq!(PolicyVersion::new(1).next(), PolicyVersion::new(2));
    }

    #[test]
    fn display() {
        assert_eq!(PolicyVersion::new(42).to_string(), "v42");
    }
}

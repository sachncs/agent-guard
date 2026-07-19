//! Key registry for JWS (JWT/DPoP/delegation) signature verification.
//!
//! Supports rotation: a new key with the same `kid` can be added while the
//! old one remains valid for a configurable grace period.
//!
//! Lives in `agentguard-core` (not `agentguard-auth`) because the registry
//! itself has no auth-specific dependencies — `Algorithm` and `KeyMaterial`
//! are the JOSE primitives, and the same registry is shared by the JWT
//! validator (`agentguard-auth`), the DPoP verifier (which doesn't
//! currently use a registry but could), and the delegation verifier
//! (`agentguard-core::delegation`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// JWS signing algorithm (RFC 7518, RFC 8725 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    /// HMAC-SHA256 (symmetric). Avoid for asymmetric protocols.
    HS256,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RS256,
    /// ECDSA with P-256 and SHA-256.
    ES256,
    /// Ed25519.
    EdDSA,
}

/// Key material — abstracted so the registry can hold heterogeneous keys.
#[derive(Debug, Clone)]
pub enum KeyMaterial {
    /// Raw HMAC secret bytes (32+ bytes for HS256).
    Hmac(Vec<u8>),
    /// PEM-encoded RSA public key.
    Rsa(Vec<u8>),
    /// PEM-encoded EC P-256 public key.
    Ecdsa(Vec<u8>),
    /// Raw 32-byte Ed25519 public key.
    Ed25519(Vec<u8>),
}

#[derive(Debug, Clone)]
struct KeyEntry {
    #[allow(dead_code)]
    kid: String,
    alg: Algorithm,
    key: KeyMaterial,
    grace_expires_at: Option<Instant>,
}

/// Thread-safe registry of trusted verification keys, keyed by `kid`.
///
/// The registry supports key rotation via [`Self::rotate`]: when a new
/// key is added under the same `kid`, the old key is preserved for the
/// grace period so tokens signed by the old key continue to verify
/// during the cutover.
///
/// Bounded by [`DEFAULT_KEY_KID_CAP`] distinct kids. When the cap is
/// reached, [`Self::add`] evicts the oldest kid before inserting the
/// new one. This prevents a misbehaving IdP with thousands of distinct
/// kids from growing the registry without bound.
#[derive(Debug)]
pub struct KeyRegistry {
    inner: parking_lot::RwLock<HashMap<String, Vec<KeyEntry>>>,
    /// Insertion order for LRU eviction. New kids are pushed to the
    /// back; `add` evicts the front when over the cap. `VecDeque` so
    /// the eviction is O(1) (the previous `Vec::remove(0)` was O(n)).
    order: parking_lot::Mutex<std::collections::VecDeque<String>>,
    cap: usize,
}

/// Default cap on the number of distinct `kid`s a [`KeyRegistry`]
/// will hold. Mirrors the cap enforced inside
/// `JwtValidator::refresh_jwks` so the two cannot drift.
pub const DEFAULT_KEY_KID_CAP: usize = 64;

impl Default for KeyRegistry {
    fn default() -> Self {
        Self::with_cap(DEFAULT_KEY_KID_CAP)
    }
}

impl KeyRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a registry with a custom kid cap (used in tests).
    pub fn with_cap(cap: usize) -> Self {
        Self {
            inner: parking_lot::RwLock::new(HashMap::new()),
            order: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            cap: cap.max(1),
        }
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Register a key. Replaces any existing active key with the same
    /// `kid` and `alg` (grace-window keys from a rotation are preserved).
    /// If the registry is at its cap, the oldest kid is evicted first.
    pub fn add(&self, kid: impl Into<String>, alg: Algorithm, key: KeyMaterial) {
        let kid = kid.into();
        let mut guard = self.inner.write();
        // Drop a stale entry (if any) so a re-add counts as an update,
        // not a new insertion, when computing capacity.
        if guard.contains_key(&kid) {
            let entries = guard.get_mut(&kid).unwrap();
            entries.retain(|e| !(e.alg == alg && e.grace_expires_at.is_none()));
        } else {
            // Cap check + evict before inserting a new kid.
            let mut order = self.order.lock();
            while order.len() >= self.cap {
                if let Some(oldest) = order.pop_front() {
                    guard.remove(&oldest);
                    tracing::warn!(
                        kid = %oldest,
                        cap = self.cap,
                        "key registry at cap; evicted oldest kid"
                    );
                } else {
                    break;
                }
            }
            order.push_back(kid.clone());
        }
        guard.entry(kid.clone()).or_default().push(KeyEntry {
            kid,
            alg,
            key,
            grace_expires_at: None,
        });
    }

    /// Register a new key under the same `kid`, marking the previous key as
    /// in grace for the given duration.
    pub fn rotate(
        &self,
        kid: impl Into<String>,
        alg: Algorithm,
        key: KeyMaterial,
        grace: Duration,
    ) {
        let kid = kid.into();
        let mut guard = self.inner.write();
        let entries = guard.entry(kid.clone()).or_default();
        for entry in entries.iter_mut() {
            entry.grace_expires_at = Some(Instant::now() + grace);
        }
        entries.push(KeyEntry {
            kid,
            alg,
            key,
            grace_expires_at: None,
        });
    }

    /// Look up a key by `kid` and `alg`. Returns all matching keys that have
    /// not yet exhausted their grace period. Returns an empty `Vec` if no
    /// matching key is found (caller decides the error mapping).
    pub fn get(&self, kid: &str, alg: Algorithm) -> Vec<KeyMaterial> {
        let guard = self.inner.read();
        let now = Instant::now();
        guard
            .get(kid)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.alg == alg)
                    .filter(|e| e.grace_expires_at.map(|t| t > now).unwrap_or(true))
                    .map(|e| e.key.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns true if a key with this `kid` is registered (any algorithm).
    pub fn contains(&self, kid: &str) -> bool {
        self.inner.read().contains_key(kid)
    }

    /// Number of distinct `kid`s registered.
    pub fn kid_count(&self) -> usize {
        self.inner.read().len()
    }
}

/// Parse a JOSE algorithm name into our [`Algorithm`] enum.
pub fn parse_alg(s: &str) -> Option<Algorithm> {
    match s {
        "HS256" => Some(Algorithm::HS256),
        "RS256" => Some(Algorithm::RS256),
        "ES256" => Some(Algorithm::ES256),
        "EdDSA" => Some(Algorithm::EdDSA),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_get_returns_key() {
        let r = KeyRegistry::new();
        r.add(
            "kid1",
            Algorithm::EdDSA,
            KeyMaterial::Ed25519(vec![0u8; 32]),
        );
        let keys = r.get("kid1", Algorithm::EdDSA);
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn rotate_preserves_old_during_grace() {
        let r = KeyRegistry::new();
        r.add(
            "kid1",
            Algorithm::EdDSA,
            KeyMaterial::Ed25519(vec![1u8; 32]),
        );
        r.rotate(
            "kid1",
            Algorithm::EdDSA,
            KeyMaterial::Ed25519(vec![2u8; 32]),
            Duration::from_secs(60),
        );
        let keys = r.get("kid1", Algorithm::EdDSA);
        assert_eq!(keys.len(), 2, "both old and new should verify during grace");
    }

    #[test]
    fn unknown_kid_returns_empty() {
        let r = KeyRegistry::new();
        assert!(r.get("missing", Algorithm::EdDSA).is_empty());
        assert!(!r.contains("missing"));
    }

    #[test]
    fn contains_returns_true_after_add() {
        let r = KeyRegistry::new();
        r.add(
            "kid1",
            Algorithm::EdDSA,
            KeyMaterial::Ed25519(vec![0u8; 32]),
        );
        assert!(r.contains("kid1"));
    }

    #[test]
    fn add_replaces_active_key() {
        let r = KeyRegistry::new();
        r.add(
            "kid1",
            Algorithm::EdDSA,
            KeyMaterial::Ed25519(vec![1u8; 32]),
        );
        r.add(
            "kid1",
            Algorithm::EdDSA,
            KeyMaterial::Ed25519(vec![2u8; 32]),
        );
        // Second add replaces the first; we expect only the new key
        // (no grace window, so the old one is gone).
        let keys = r.get("kid1", Algorithm::EdDSA);
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn cap_evicts_oldest_kid() {
        let r = KeyRegistry::with_cap(3);
        for i in 0..5 {
            r.add(
                format!("kid{i}"),
                Algorithm::EdDSA,
                KeyMaterial::Ed25519(vec![i as u8; 32]),
            );
        }
        // Only the last 3 kids are retained.
        assert_eq!(r.kid_count(), 3);
        assert!(!r.contains("kid0"));
        assert!(!r.contains("kid1"));
        assert!(r.contains("kid2"));
        assert!(r.contains("kid3"));
        assert!(r.contains("kid4"));
    }

    #[test]
    fn rotate_under_cap_does_not_evict() {
        let r = KeyRegistry::with_cap(4);
        r.add("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(vec![1; 32]));
        // Re-adding the same kid updates in place; no eviction.
        r.add("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(vec![2; 32]));
        assert_eq!(r.kid_count(), 1);
    }
}

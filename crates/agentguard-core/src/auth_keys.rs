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
#[derive(Debug, Default)]
pub struct KeyRegistry {
    inner: parking_lot::RwLock<HashMap<String, Vec<KeyEntry>>>,
}

impl KeyRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a key. Replaces any existing active key with the same
    /// `kid` and `alg` (grace-window keys from a rotation are preserved).
    pub fn add(&self, kid: impl Into<String>, alg: Algorithm, key: KeyMaterial) {
        let mut guard = self.inner.write();
        let entry = KeyEntry {
            kid: kid.into(),
            alg,
            key,
            grace_expires_at: None,
        };
        // Replace existing entries with the same kid+alg rather than
        // appending. Without this, every JWKS refresh (which calls add
        // for every JWKS doc key) grows the registry without bound and
        // a long-running process eventually OOMs.
        let entries = guard.entry(entry.kid.clone()).or_default();
        entries.retain(|e| !(e.alg == entry.alg && e.grace_expires_at.is_none()));
        entries.push(entry);
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
        r.add("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(vec![0u8; 32]));
        assert!(r.contains("kid1"));
    }

    #[test]
    fn add_replaces_active_key() {
        let r = KeyRegistry::new();
        r.add("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(vec![1u8; 32]));
        r.add("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(vec![2u8; 32]));
        // Second add replaces the first; we expect only the new key
        // (no grace window, so the old one is gone).
        let keys = r.get("kid1", Algorithm::EdDSA);
        assert_eq!(keys.len(), 1);
    }
}
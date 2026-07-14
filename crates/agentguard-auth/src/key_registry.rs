//! Key registry for JWT/Delegation token signature verification.
//!
//! Supports rotation: a new key with the same `kid` can be added while the
//! old one remains valid for a configurable grace period.

use crate::error::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// JWT/Delegation signing algorithm (RFC 8725 §3.1).
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
pub(crate) struct KeyEntry {
    pub(crate) kid: String,
    pub(crate) alg: Algorithm,
    pub(crate) key: KeyMaterial,
    pub(crate) grace_expires_at: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct KeyRegistry {
    inner: RwLock<HashMap<String, Vec<KeyEntry>>>,
}

impl KeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a key. Replaces any existing key with the same `kid` and `alg`.
    pub fn add(&self, kid: impl Into<String>, alg: Algorithm, key: KeyMaterial) -> Result<()> {
        let mut guard = self.inner.write().expect("KeyRegistry poisoned");
        let entry = KeyEntry {
            kid: kid.into(),
            alg,
            key,
            grace_expires_at: None,
        };
        guard.entry(entry.kid.clone()).or_default().push(entry);
        Ok(())
    }

    /// Register a new key under the same `kid`, marking the previous key as
    /// in grace for the given duration.
    pub fn rotate(
        &self,
        kid: impl Into<String>,
        alg: Algorithm,
        key: KeyMaterial,
        grace: Duration,
    ) -> Result<()> {
        let kid = kid.into();
        let mut guard = self.inner.write().expect("KeyRegistry poisoned");
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
        Ok(())
    }

    /// Look up a key by `kid` and `alg`. Returns all matching keys that have
    /// not yet exhausted their grace period.
    pub fn get(&self, kid: &str, alg: Algorithm) -> Result<Vec<KeyMaterial>> {
        let guard = self.inner.read().expect("KeyRegistry poisoned");
        let now = Instant::now();
        let entries = guard
            .get(kid)
            .ok_or_else(|| AuthError::JwtUnknownKid(kid.to_string()))?;
        let active: Vec<KeyMaterial> = entries
            .iter()
            .filter(|e| e.alg == alg)
            .filter(|e| e.grace_expires_at.map(|t| t > now).unwrap_or(true))
            .map(|e| e.key.clone())
            .collect();
        if active.is_empty() {
            return Err(AuthError::JwtUnknownKid(kid.to_string()));
        }
        Ok(active)
    }

    pub fn kid_count(&self) -> usize {
        self.inner.read().expect("KeyRegistry poisoned").len()
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
        )
        .unwrap();
        let keys = r.get("kid1", Algorithm::EdDSA).unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn rotate_preserves_old_during_grace() {
        let r = KeyRegistry::new();
        r.add(
            "kid1",
            Algorithm::EdDSA,
            KeyMaterial::Ed25519(vec![1u8; 32]),
        )
        .unwrap();
        r.rotate(
            "kid1",
            Algorithm::EdDSA,
            KeyMaterial::Ed25519(vec![2u8; 32]),
            Duration::from_secs(60),
        )
        .unwrap();
        let keys = r.get("kid1", Algorithm::EdDSA).unwrap();
        assert_eq!(keys.len(), 2, "both old and new should verify during grace");
    }

    #[test]
    fn unknown_kid_errors() {
        let r = KeyRegistry::new();
        assert!(matches!(
            r.get("missing", Algorithm::EdDSA),
            Err(AuthError::JwtUnknownKid(_))
        ));
    }
}

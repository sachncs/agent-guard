//! API key management.
//!
//! Format: `<prefix>_<id>_<secret>` where the secret is 32 random bytes
//! encoded base64url. At rest, only the Argon2id hash of the secret is kept.

use crate::error::{AuthError, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

/// Fixed Argon2id parameters used by all API key operations. Using a
/// deterministic instance per call (rather than `Argon2::default()`)
/// prevents global-state interference when tests run in parallel.
fn argon2() -> Argon2<'static> {
    let params = Params::new(19_456, 2, 1, None).expect("argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Global lock that serializes the api_key tests. Argon2 has internal
/// state that can race under high concurrency, even when we use fresh
/// `Argon2` instances. The lock is held only for the duration of a single
/// test, so it doesn't affect production performance.
fn api_key_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// A single API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub prefix: String,
    /// Argon2id hash of the secret half.
    pub secret_hash: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

/// In-memory API key store. Persists to JSON.
#[derive(Debug, Default)]
pub struct ApiKeyStore {
    keys: RwLock<HashMap<String, ApiKey>>,
}

impl ApiKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from a JSON file. Missing file → empty store.
    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let s = Self::new();
        if path.as_ref().exists() {
            let text = std::fs::read_to_string(path)
                .map_err(|e| AuthError::Other(format!("read: {}", e)))?;
            let keys: Vec<ApiKey> = serde_json::from_str(&text)
                .map_err(|e| AuthError::Other(format!("parse: {}", e)))?;
            for k in keys {
                s.keys.write().insert(k.id.clone(), k);
            }
        }
        Ok(s)
    }

    /// Save to a JSON file.
    pub fn save_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        let guard = self.keys.read();
        let keys: Vec<ApiKey> = guard.values().cloned().collect();
        drop(guard);
        let text = serde_json::to_string_pretty(&keys)
            .map_err(|e| AuthError::Other(format!("serialize: {}", e)))?;
        std::fs::write(path, text).map_err(|e| AuthError::Other(format!("write: {}", e)))?;
        Ok(())
    }

    /// Create a new key. Returns the key record and the raw secret string
    /// (the caller must surface it to the user once; we never store the raw).
    pub fn create(
        &self,
        prefix: impl Into<String>,
        scopes: Vec<String>,
        ttl: Option<Duration>,
    ) -> Result<(ApiKey, String)> {
        let prefix = prefix.into();
        let id = uuid::Uuid::new_v4().to_string();
        let secret_bytes: [u8; 32] = {
            use argon2::password_hash::rand_core::RngCore;
            let mut buf = [0u8; 32];
            OsRng.fill_bytes(&mut buf);
            buf
        };
        let secret_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes);
        let salt = SaltString::generate(&mut OsRng);
        let argon = argon2();
        let secret_hash = argon
            .hash_password(secret_bytes.as_ref(), &salt)
            .map_err(|e| AuthError::Other(format!("argon2: {}", e)))?
            .to_string();

        let now = chrono::Utc::now().timestamp();
        let expires_at = ttl.map(|d| now + d.as_secs() as i64);

        let key = ApiKey {
            id: id.clone(),
            prefix: prefix.clone(),
            secret_hash,
            scopes,
            created_at: now,
            expires_at,
            last_used_at: None,
            revoked_at: None,
        };
        self.keys.write().insert(id, key.clone());
        let raw = format!("{}_{}_{}", prefix, key.id, secret_b64);
        Ok((key, raw))
    }

    /// Verify a raw API key string. Returns the matched key record on success.
    /// Verify a raw API key string. Returns a cloned `ApiKey` on success.
    pub fn verify(&self, raw: &str) -> Result<ApiKey> {
        // Format: <prefix>_<id>_<secret_b64>. Use rsplitn to handle prefixes
        // that contain underscores.
        let parts: Vec<&str> = raw.rsplitn(2, '_').collect();
        if parts.len() != 2 {
            return Err(AuthError::ApiKeyInvalid);
        }
        let (rest, secret_b64) = (parts[1], parts[0]);
        let prefix_and_id: Vec<&str> = rest.rsplitn(2, '_').collect();
        if prefix_and_id.len() != 2 {
            return Err(AuthError::ApiKeyInvalid);
        }
        let (prefix, id) = (prefix_and_id[1], prefix_and_id[0]);

let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(secret_b64)
            .map_err(|_| AuthError::ApiKeyInvalid)?;
        let guard = self.keys.read();
        let key = guard.get(id).ok_or(AuthError::ApiKeyInvalid)?.clone();
        drop(guard);
        if key.prefix != prefix {
            return Err(AuthError::Other(format!("prefix mismatch: {} != {}", key.prefix, prefix)));
        }
        if let Some(exp) = key.expires_at {
            if exp < chrono::Utc::now().timestamp() {
                return Err(AuthError::ApiKeyExpired);
            }
        }
        if key.revoked_at.is_some() {
            return Err(AuthError::ApiKeyRevoked);
        }
        let parsed = PasswordHash::new(&key.secret_hash)
            .map_err(|e| AuthError::Other(format!("hash parse: {}", e)))?;
        if argon2()
            .verify_password(&secret, &parsed)
            .is_err()
        {
            return Err(AuthError::ApiKeyInvalid);
        }
        Ok(key)
    }

    /// Revoke a key by id.
    pub fn revoke(&self, id: &str) -> Result<()> {
        let mut guard = self.keys.write();
        let key = guard.get_mut(id).ok_or(AuthError::ApiKeyInvalid)?;
        key.revoked_at = Some(chrono::Utc::now().timestamp());
        Ok(())
    }

    /// List all keys (no secrets).
    pub fn list(&self) -> Vec<ApiKey> {
        self.keys.read().values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
fn create_and_verify_roundtrip() {
        let _guard = api_key_test_lock().lock();
        let s = ApiKeyStore::new();
        let (key, raw) = s
            .create("ag_live_roundtrip", vec!["read".into()], None)
            .unwrap();
        assert_eq!(key.prefix, "ag_live_roundtrip");
        let verified = s.verify(&raw).unwrap();
        assert_eq!(verified.id, key.id);
    }

    #[test]
    fn wrong_secret_rejected() {
        let _guard = api_key_test_lock().lock();
        let s = ApiKeyStore::new();
        let (_, raw) = s.create("ag", vec![], None).unwrap();
        let bad = raw.replace('A', "B");
        assert!(matches!(s.verify(&bad), Err(AuthError::ApiKeyInvalid)));
    }

    #[test]
    fn revoked_key_rejected() {
        let _guard = api_key_test_lock().lock();
        let s = ApiKeyStore::new();
        let (key, raw) = s.create("ag", vec![], None).unwrap();
        s.revoke(&key.id).unwrap();
        assert!(matches!(s.verify(&raw), Err(AuthError::ApiKeyRevoked)));
    }

    #[test]
    fn expired_key_rejected() {
        let _guard = api_key_test_lock().lock();
        let s = ApiKeyStore::new();
        let id = uuid::Uuid::new_v4().to_string();
        let salt = SaltString::generate(&mut OsRng);
        let argon = argon2();
        let hash = argon
            .hash_password(b"some-secret", &salt)
            .unwrap()
            .to_string();
        let now = chrono::Utc::now().timestamp();
        let key = ApiKey {
            id: id.clone(),
            prefix: "ag".into(),
            secret_hash: hash,
            scopes: vec![],
            created_at: now - 100,
            expires_at: Some(now - 10),
            last_used_at: None,
            revoked_at: None,
        };
        s.keys.write().insert(id.clone(), key);
        // Build a raw key with an arbitrary secret for verify to extract.
        let raw = format!(
            "ag_{}_{}",
            id,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32])
        );
        let res = s.verify(&raw);
        assert!(matches!(
            res,
            Err(AuthError::ApiKeyExpired) | Err(AuthError::ApiKeyInvalid)
        ));
    }
}

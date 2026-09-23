//! API key management.
//!
//! Format: `<prefix>:<id>:<secret>` where the secret is 32 random bytes
//! encoded base64url. The `:` separator avoids ambiguity with the
//! base64url alphabet (which includes `_` and `-`). At rest, only the
//! Argon2id hash of the secret is kept.

use crate::error::{AuthError, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Fixed Argon2id parameters used by all API key operations. Using a
/// deterministic instance per call (rather than `Argon2::default()`)
/// prevents global-state interference when tests run in parallel.
///
/// Parameters: 64 MiB memory, t=3, p=4. This is OWASP's 2024 production
/// recommendation for auth secrets. The previous 19 MiB / t=2 / p=1
/// was at the bottom of OWASP's "acceptable" range and ~10x cheaper
/// to brute-force; the bump brings verification to ~150ms on server
/// hardware, which is appropriate for an authentication boundary.
fn argon2() -> Result<Argon2<'static>> {
    let params = Params::new(64 * 1024, 3, 4, None)
        .map_err(|e| AuthError::Other(format!("argon2 params: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Global lock that serializes the api_key tests. Argon2 has internal
/// state that can race under high concurrency, even when we use fresh
/// `Argon2` instances. The lock is held only for the duration of a single
/// test, so it doesn't affect production performance.
#[cfg(test)]
fn api_key_test_lock() -> &'static parking_lot::Mutex<()> {
    static LOCK: std::sync::OnceLock<parking_lot::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| parking_lot::Mutex::new(()))
}

/// A single API key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub prefix: String,
    /// Argon2id hash of the secret half.
    pub secret_hash: String,
    pub scopes: Vec<String>,
    /// Required request identity binding for standalone PDP decision routes.
    /// The explicit `authorize:any` capability may act on another subject,
    /// but the key still has a service identity for attribution and tenancy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ApiKeyIdentity>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

/// Cedar identity a standalone API key is allowed to represent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyIdentity {
    pub subject_type: String,
    pub subject_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

impl ApiKeyIdentity {
    pub fn new(
        subject_type: impl Into<String>,
        subject_id: impl Into<String>,
        tenant_id: Option<String>,
    ) -> Result<Self> {
        let subject_type = subject_type.into();
        let subject_id = subject_id.into();
        if !matches!(subject_type.as_str(), "User" | "Agent") || subject_id.trim().is_empty() {
            return Err(AuthError::Other(
                "API key identity must use User or Agent with a non-empty subject id".into(),
            ));
        }
        if tenant_id
            .as_ref()
            .is_some_and(|tenant| tenant.trim().is_empty())
        {
            return Err(AuthError::Other(
                "API key tenant id must be non-empty when provided".into(),
            ));
        }
        let subject_id = subject_id.trim().to_owned();
        let tenant_id = tenant_id.map(|tenant| tenant.trim().to_owned());
        Ok(Self {
            subject_type,
            subject_id,
            tenant_id,
        })
    }
}

impl ApiKey {
    /// Whether the key grants a named capability. `*` grants all scopes.
    pub fn has_scope(&self, required: &str) -> bool {
        required.is_empty()
            || self
                .scopes
                .iter()
                .any(|scope| scope == "*" || scope == required)
    }
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
        s.reload_from_file(path)?;
        Ok(s)
    }

    /// Atomically replace the in-memory key set from a complete persisted
    /// snapshot. A parse or I/O failure leaves the currently active set
    /// untouched, so a partial secret projection cannot erase valid keys.
    pub fn reload_from_file(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        let path = path.as_ref();
        let keys = if path.exists() {
            let text = std::fs::read_to_string(path)
                .map_err(|e| AuthError::Other(format!("read: {}", e)))?;
            let parsed: Vec<ApiKey> = serde_json::from_str(&text)
                .map_err(|e| AuthError::Other(format!("parse: {}", e)))?;
            let mut keys = HashMap::with_capacity(parsed.len());
            for key in parsed {
                validate_api_key_record(&key)?;
                let id = key.id.clone();
                if keys.insert(id.clone(), key).is_some() {
                    return Err(AuthError::Other(format!(
                        "duplicate API-key id in store: {id}"
                    )));
                }
            }
            keys
        } else {
            HashMap::new()
        };
        *self.keys.write() = keys;
        Ok(())
    }

    /// Save to a JSON file.
    pub fn save_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        use std::io::Write;

        let path = path.as_ref();
        let guard = self.keys.read();
        let mut keys: Vec<ApiKey> = guard.values().cloned().collect();
        drop(guard);
        keys.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then(left.id.cmp(&right.id))
        });
        let text = serde_json::to_string_pretty(&keys)
            .map_err(|e| AuthError::Other(format!("serialize: {}", e)))?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let name = path
            .file_name()
            .ok_or_else(|| AuthError::Other("API-key store path has no filename".into()))?;
        let temporary = parent.join(format!(
            ".{}.{}.tmp",
            name.to_string_lossy(),
            uuid::Uuid::new_v4()
        ));

        let write_result = (|| -> std::io::Result<()> {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            #[cfg(windows)]
            if path.exists() {
                std::fs::remove_file(path)?;
            }
            std::fs::rename(&temporary, path)?;
            #[cfg(unix)]
            std::fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = std::fs::remove_file(&temporary);
            return Err(AuthError::Other(format!("write: {}", error)));
        }
        Ok(())
    }

    /// Create a new key. Returns the key record and the raw secret string
    /// (the caller must surface it to the user once; we never store the raw).
    ///
    /// # Errors
    /// Returns `AuthError::Other` if Argon2 fails (extremely rare; only
    /// happens on out-of-memory).
    ///
    /// # Examples
    /// ```
    /// use agentguard_auth::ApiKeyStore;
    /// use std::time::Duration;
    /// let store = ApiKeyStore::new();
    /// let (key, raw) = store.create("ag_live", vec!["read".into()], Some(Duration::from_secs(3600))).unwrap();
    /// assert_eq!(key.prefix, "ag_live");
    /// // Surface `raw` to the user once. It looks like: ag_live_<uuid>_<base64>
    /// ```
    pub fn create(
        &self,
        prefix: impl Into<String>,
        scopes: Vec<String>,
        ttl: Option<Duration>,
    ) -> Result<(ApiKey, String)> {
        self.create_with_identity(prefix.into(), scopes, ttl, None)
    }

    /// Create a key bound to one Cedar subject and optional tenant.
    /// Decision routes accept only identity-bound keys and require the
    /// `authorize` scope (or `*`).
    pub fn create_bound(
        &self,
        prefix: impl Into<String>,
        scopes: Vec<String>,
        ttl: Option<Duration>,
        identity: ApiKeyIdentity,
    ) -> Result<(ApiKey, String)> {
        let identity = ApiKeyIdentity::new(
            identity.subject_type,
            identity.subject_id,
            identity.tenant_id,
        )?;
        self.create_with_identity(prefix.into(), scopes, ttl, Some(identity))
    }

    fn create_with_identity(
        &self,
        prefix: String,
        scopes: Vec<String>,
        ttl: Option<Duration>,
        identity: Option<ApiKeyIdentity>,
    ) -> Result<(ApiKey, String)> {
        if prefix.trim().is_empty() || prefix.trim() != prefix || prefix.contains(':') {
            return Err(AuthError::Other(
                "API key prefix must be non-empty and must not contain ':'".into(),
            ));
        }
        if scopes.iter().any(|scope| !valid_scope(scope)) {
            return Err(AuthError::Other(
                "API-key scopes must be non-empty and contain no whitespace".into(),
            ));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let secret_bytes: [u8; 32] = {
            use argon2::password_hash::rand_core::RngCore;
            let mut buf = [0u8; 32];
            OsRng.fill_bytes(&mut buf);
            buf
        };
        let secret_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes);
        let salt = SaltString::generate(&mut OsRng);
        let argon = argon2()?;
        let secret_hash = argon
            .hash_password(secret_bytes.as_ref(), &salt)
            .map_err(|e| AuthError::Other(format!("argon2: {}", e)))?
            .to_string();

        let now = chrono::Utc::now().timestamp();
        let expires_at = match ttl {
            Some(duration) => {
                let seconds = i64::try_from(duration.as_secs()).map_err(|_| {
                    AuthError::Other("API key TTL exceeds the supported timestamp range".into())
                })?;
                Some(now.checked_add(seconds).ok_or_else(|| {
                    AuthError::Other("API key expiry exceeds the supported timestamp range".into())
                })?)
            }
            None => None,
        };

        let key = ApiKey {
            id: id.clone(),
            prefix: prefix.clone(),
            secret_hash,
            scopes,
            identity,
            created_at: now,
            expires_at,
            last_used_at: None,
            revoked_at: None,
        };
        self.keys.write().insert(id, key.clone());
        let raw = format!("{}:{}:{}", prefix, key.id, secret_b64);
        Ok((key, raw))
    }

    /// Verify a raw API key string. Returns a cloned `ApiKey` on success.
    ///
    /// Format: `<prefix>:<id>:<base64url-secret>`. The `:` separator ensures
    /// the parse is unambiguous even when the prefix or secret contain `_`
    /// (which is in the base64url alphabet).
    pub fn verify(&self, raw: &str) -> Result<ApiKey> {
        let parts: Vec<&str> = raw.split(':').collect();
        if parts.len() != 3 {
            return Err(AuthError::ApiKeyInvalid);
        }
        let (prefix, id, secret_b64) = (parts[0], parts[1], parts[2]);

        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(secret_b64)
            .map_err(|_| AuthError::ApiKeyInvalid)?;
        let guard = self.keys.read();
        let key = guard.get(id).ok_or(AuthError::ApiKeyInvalid)?.clone();
        drop(guard);
        if key.prefix != prefix {
            return Err(AuthError::Other(format!(
                "prefix mismatch: {} != {}",
                key.prefix, prefix
            )));
        }
        if let Some(exp) = key.expires_at {
            if exp <= chrono::Utc::now().timestamp() {
                return Err(AuthError::ApiKeyExpired);
            }
        }
        if key.revoked_at.is_some() {
            return Err(AuthError::ApiKeyRevoked);
        }
        let parsed = PasswordHash::new(&key.secret_hash)
            .map_err(|e| AuthError::Other(format!("hash parse: {}", e)))?;
        if argon2()?.verify_password(&secret, &parsed).is_err() {
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

/// Validate persisted records before they become the live authentication set.
/// In particular, the PHC parameters control verification cost; an operator
/// typo or corrupted snapshot must not introduce unbounded Argon2 work on the
/// request path. Legacy hashes with lower costs remain readable.
fn validate_api_key_record(key: &ApiKey) -> Result<()> {
    if key.id.trim().is_empty() || key.id.trim() != key.id || key.id.contains(':') {
        return Err(AuthError::Other(
            "API-key id must be non-empty and contain no ':'".into(),
        ));
    }
    if key.prefix.trim().is_empty() || key.prefix.trim() != key.prefix || key.prefix.contains(':') {
        return Err(AuthError::Other(
            "API-key prefix must be non-empty and contain no ':'".into(),
        ));
    }
    if key.scopes.iter().any(|scope| !valid_scope(scope)) {
        return Err(AuthError::Other(
            "API-key scopes must be non-empty and contain no whitespace".into(),
        ));
    }
    if let Some(identity) = &key.identity {
        let normalized = ApiKeyIdentity::new(
            identity.subject_type.clone(),
            identity.subject_id.clone(),
            identity.tenant_id.clone(),
        )?;
        if &normalized != identity {
            return Err(AuthError::Other(
                "API-key identity fields must be trimmed".into(),
            ));
        }
    }

    let hash = PasswordHash::new(&key.secret_hash)
        .map_err(|_| AuthError::Other("API-key store contains an invalid password hash".into()))?;
    let params = &hash.params;
    let memory_kib = params.get_decimal("m");
    let iterations = params.get_decimal("t");
    let parallelism = params.get_decimal("p");
    if hash.algorithm.as_str() != "argon2id"
        || hash.version != Some(19)
        || hash.salt.is_none()
        || hash.hash.is_none()
        || memory_kib.is_none_or(|value| !(8..=65_536).contains(&value))
        || iterations.is_none_or(|value| !(1..=3).contains(&value))
        || parallelism.is_none_or(|value| !(1..=4).contains(&value))
        || memory_kib.unwrap_or_default() < parallelism.unwrap_or_default() * 8
    {
        return Err(AuthError::Other(
            "API-key hash must use bounded Argon2id v19 parameters".into(),
        ));
    }
    Ok(())
}

fn valid_scope(scope: &str) -> bool {
    !scope.trim().is_empty() && !scope.bytes().any(|byte| byte.is_ascii_whitespace())
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
    fn bound_key_persists_identity_and_scope() {
        let _guard = api_key_test_lock().lock();
        let store = ApiKeyStore::new();
        let identity = ApiKeyIdentity::new("Agent", "research", Some("tenant-a".into())).unwrap();
        let (created, raw) = store
            .create_bound("ag", vec!["authorize".into()], None, identity.clone())
            .unwrap();
        let verified = store.verify(&raw).unwrap();
        assert_eq!(verified.identity, Some(identity));
        assert!(verified.has_scope("authorize"));
        assert!(!verified.has_scope("metrics:read"));
        assert!(created.has_scope("authorize"));
    }

    #[test]
    fn identity_rejects_unknown_subject_type_and_empty_fields() {
        assert!(ApiKeyIdentity::new("Service", "svc", None).is_err());
        assert!(ApiKeyIdentity::new("User", "  ", None).is_err());
        assert!(ApiKeyIdentity::new("Agent", "agent", Some(" ".into())).is_err());
    }

    #[test]
    fn key_creation_rejects_invalid_prefix_and_expiry_overflow() {
        let _guard = api_key_test_lock().lock();
        let store = ApiKeyStore::new();
        assert!(store.create("", vec![], None).is_err());
        assert!(store.create(" ag ", vec![], None).is_err());
        assert!(store.create("bad:prefix", vec![], None).is_err());
        assert!(store.create("ag", vec!["bad scope".into()], None).is_err());
        assert!(store
            .create("ag", vec![], Some(Duration::from_secs(u64::MAX)))
            .is_err());
    }

    #[test]
    fn legacy_api_key_json_remains_readable_but_unbound() {
        let legacy = serde_json::json!({
            "id": "legacy",
            "prefix": "ag",
            "secret_hash": "hash",
            "scopes": [],
            "created_at": 0,
            "expires_at": null,
            "last_used_at": null,
            "revoked_at": null
        });
        let key: ApiKey = serde_json::from_value(legacy).unwrap();
        assert!(key.identity.is_none());
    }

    #[test]
    fn save_to_file_replaces_complete_store_with_restrictive_permissions() {
        let _guard = api_key_test_lock().lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let store = ApiKeyStore::new();
        store.save_to_file(&path).unwrap();
        let first = std::fs::read(&path).unwrap();
        store
            .create_bound(
                "ag",
                vec!["authorize".into()],
                None,
                ApiKeyIdentity::new("User", "alice", None).unwrap(),
            )
            .unwrap();
        store.save_to_file(&path).unwrap();
        let second = std::fs::read(&path).unwrap();
        assert_ne!(first, second);
        assert_eq!(ApiKeyStore::load_from_file(&path).unwrap().list().len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "temporary files should be removed after atomic replacement"
        );
    }

    #[test]
    fn reload_preserves_last_good_keys_when_replacement_snapshot_is_invalid() {
        let _guard = api_key_test_lock().lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let admin = ApiKeyStore::new();
        let (key, raw) = admin
            .create_bound(
                "ag",
                vec!["authorize".into()],
                None,
                ApiKeyIdentity::new("User", "alice", None).unwrap(),
            )
            .unwrap();
        admin.save_to_file(&path).unwrap();
        let live = ApiKeyStore::load_from_file(&path).unwrap();
        live.verify(&raw).unwrap();

        std::fs::write(&path, b"not-json").unwrap();
        assert!(live.reload_from_file(&path).is_err());
        live.verify(&raw)
            .expect("invalid snapshots retain the last known-good key set");

        let mut malformed = admin.list();
        malformed[0].secret_hash = "not-a-phc-hash".into();
        std::fs::write(&path, serde_json::to_vec(&malformed).unwrap()).unwrap();
        assert!(live.reload_from_file(&path).is_err());
        live.verify(&raw)
            .expect("malformed hash snapshots retain the last known-good key set");

        let mut unbounded_cost = admin.list();
        unbounded_cost[0].secret_hash = key.secret_hash.replace("m=65536", "m=65537");
        assert_ne!(unbounded_cost[0].secret_hash, key.secret_hash);
        std::fs::write(&path, serde_json::to_vec(&unbounded_cost).unwrap()).unwrap();
        assert!(live.reload_from_file(&path).is_err());
        live.verify(&raw)
            .expect("unbounded hash-cost snapshots retain the last known-good key set");

        let mut duplicate = admin.list();
        duplicate.push(duplicate[0].clone());
        std::fs::write(&path, serde_json::to_vec(&duplicate).unwrap()).unwrap();
        assert!(live.reload_from_file(&path).is_err());
        live.verify(&raw)
            .expect("duplicate ids must not overwrite the active key set");

        admin.revoke(&key.id).unwrap();
        admin.save_to_file(&path).unwrap();
        live.reload_from_file(&path).unwrap();
        assert!(matches!(live.verify(&raw), Err(AuthError::ApiKeyRevoked)));
    }

    #[test]
    fn wrong_secret_rejected() {
        let _guard = api_key_test_lock().lock();
        let s = ApiKeyStore::new();
        let (_, mut raw) = s.create("ag", vec![], None).unwrap();
        // Corrupt the secret by flipping the last character of the base64.
        let last = raw.pop().unwrap();
        let replacement = if last == 'A' { 'B' } else { 'A' };
        let bad = format!("{}{}", raw, replacement);
        let res = s.verify(&bad);
        assert!(matches!(res, Err(AuthError::ApiKeyInvalid)));
    }

    #[test]
    fn revoked_key_rejected() {
        let _guard = api_key_test_lock().lock();
        let s = ApiKeyStore::new();
        let (key, raw) = s.create("ag", vec![], None).unwrap();
        s.revoke(&key.id).unwrap();
        let res = s.verify(&raw);
        assert!(matches!(res, Err(AuthError::ApiKeyRevoked)));
    }

    #[test]
    fn expired_key_rejected() {
        let _guard = api_key_test_lock().lock();
        let s = ApiKeyStore::new();
        let (key, raw) = s.create("ag", vec![], None).unwrap();
        s.keys.write().get_mut(&key.id).unwrap().expires_at = Some(chrono::Utc::now().timestamp());
        assert!(matches!(s.verify(&raw), Err(AuthError::ApiKeyExpired)));
    }
}

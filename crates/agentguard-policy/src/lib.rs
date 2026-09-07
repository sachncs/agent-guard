//! Policy operations: versioned bundles, hot reload, diff, blast radius.
//!
//! v2.0: provides:
//! - [`PolicyVersion`] — monotonic version identifiers
//! - [`PolicyBundle`] — a snapshot of schema + policies, addressable by version
//! - [`BundleRegistry`] — in-memory version store with persistence
//! - [`diff`] — line-level diff between two bundles (uses the `similar` crate)
//! - [`blast_radius::analyze`] — classify decision changes across a corpus
//! - hot-reload watcher (gated behind the `watch` feature, enabled by default)

pub mod blast_radius;
pub mod diff;
pub mod version;

#[cfg(feature = "watch")]
pub mod watcher;

pub use version::PolicyVersion;

use agentguard_core::Result;

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::SystemTime;

/// A policy bundle: schema + named policy sources, identified by version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub version: PolicyVersion,
    pub tenant_id: String,
    pub schema_hash: [u8; 32],
    pub policies_hash: [u8; 32],
    pub created_at: i64,
    pub created_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
    pub schema_source: String,
    pub policies: Vec<NamedPolicy>,
}

/// A single named policy within a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedPolicy {
    pub id: String,
    pub source: String,
}

impl PolicyBundle {
    /// Compute a stable hash for this bundle (schema hash + policies hash).
    pub fn content_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.schema_hash);
        hasher.update(self.policies_hash);
        hasher.finalize().into()
    }
}

/// In-memory registry of policy bundles, keyed by version, scoped per tenant.
#[derive(Debug, Default)]
pub struct BundleRegistry {
    /// tenant_id -> version -> bundle
    by_tenant: parking_lot::RwLock<
        std::collections::HashMap<String, std::collections::BTreeMap<u64, PolicyBundle>>,
    >,
}

impl BundleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a bundle. Replaces any existing bundle at the same
    /// `(tenant, version)`.
    pub fn register(&self, bundle: PolicyBundle) -> Result<()> {
        let mut all = self.by_tenant.write();
        let entry = all.entry(bundle.tenant_id.clone()).or_default();
        entry.insert(bundle.version.as_u64(), bundle);
        Ok(())
    }

    /// Get the latest bundle for a tenant, if any.
    pub fn latest(&self, tenant_id: &str) -> Option<PolicyBundle> {
        let all = self.by_tenant.read();
        all.get(tenant_id)
            .and_then(|m| m.values().next_back().cloned())
    }

    /// Get a specific version of a tenant's bundle.
    pub fn at(&self, tenant_id: &str, version: PolicyVersion) -> Option<PolicyBundle> {
        let all = self.by_tenant.read();
        all.get(tenant_id)
            .and_then(|m| m.get(&version.as_u64()).cloned())
    }

    /// List all versions for a tenant, oldest first.
    pub fn list(&self, tenant_id: &str) -> Vec<PolicyBundle> {
        let all = self.by_tenant.read();
        all.get(tenant_id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Total number of bundles across all tenants.
    pub fn total(&self) -> usize {
        let all = self.by_tenant.read();
        all.values().map(|m| m.len()).sum()
    }
}

/// Helper: hash a string with SHA-256.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Helper: current Unix timestamp.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Helper: write a bundle to disk as JSON.
pub fn write_bundle_to_path(bundle: &PolicyBundle, path: impl AsRef<Path>) -> std::io::Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(bundle).map_err(std::io::Error::other)?;
    std::fs::write(path, text)?;
    Ok(())
}

/// Helper: read a bundle from disk.
pub fn read_bundle_from_path(path: impl AsRef<Path>) -> std::io::Result<PolicyBundle> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(version: u64, tenant: &str) -> PolicyBundle {
        PolicyBundle {
            version: PolicyVersion::new(version),
            tenant_id: tenant.to_string(),
            schema_hash: [0u8; 32],
            policies_hash: [0u8; 32],
            created_at: now_unix(),
            created_by: "test".into(),
            signature: None,
            schema_source: "entity User;".into(),
            policies: vec![NamedPolicy {
                id: "p0".into(),
                source: "permit (principal, action, resource);".into(),
            }],
        }
    }

    #[test]
    fn registry_keeps_latest() {
        let reg = BundleRegistry::new();
        reg.register(bundle(1, "acme")).unwrap();
        reg.register(bundle(2, "acme")).unwrap();
        reg.register(bundle(3, "acme")).unwrap();
        let latest = reg.latest("acme").unwrap();
        assert_eq!(latest.version.as_u64(), 3);
        assert_eq!(reg.list("acme").len(), 3);
    }

    #[test]
    fn at_returns_specific_version() {
        let reg = BundleRegistry::new();
        reg.register(bundle(1, "acme")).unwrap();
        reg.register(bundle(5, "acme")).unwrap();
        let v = reg.at("acme", PolicyVersion::new(5)).unwrap();
        assert_eq!(v.version.as_u64(), 5);
        assert!(reg.at("acme", PolicyVersion::new(99)).is_none());
    }

    #[test]
    fn tenants_are_isolated() {
        let reg = BundleRegistry::new();
        reg.register(bundle(1, "acme")).unwrap();
        reg.register(bundle(2, "globex")).unwrap();
        assert_eq!(reg.latest("acme").unwrap().version.as_u64(), 1);
        assert_eq!(reg.latest("globex").unwrap().version.as_u64(), 2);
    }

    #[test]
    fn content_hash_is_stable() {
        let a = bundle(1, "t");
        let b = bundle(1, "t");
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn round_trip_via_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.json");
        let b = bundle(7, "tenant-x");
        write_bundle_to_path(&b, &path).unwrap();
        let loaded = read_bundle_from_path(&path).unwrap();
        assert_eq!(loaded.version.as_u64(), 7);
        assert_eq!(loaded.tenant_id, "tenant-x");
        assert_eq!(loaded.policies.len(), 1);
    }
}

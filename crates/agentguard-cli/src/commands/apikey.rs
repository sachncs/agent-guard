//! Operator commands for managing standalone PDP API-key records.

use agentguard_auth::{ApiKeyIdentity, ApiKeyStore};
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::path::Path;
use std::time::Duration;

pub struct CreateKeyOptions<'a> {
    pub path: &'a Path,
    pub prefix: &'a str,
    pub subject_type: &'a str,
    pub subject_id: &'a str,
    pub tenant_id: Option<&'a str>,
    pub scopes: Vec<String>,
    pub ttl_seconds: u64,
}

pub fn create(options: CreateKeyOptions<'_>, output: &str) -> Result<()> {
    if options.ttl_seconds == 0 {
        bail!("--ttl-seconds must be greater than zero");
    }
    if options.scopes.is_empty() || options.scopes.iter().any(|scope| scope.trim().is_empty()) {
        bail!("at least one non-empty --scope is required");
    }
    let identity = ApiKeyIdentity::new(
        options.subject_type,
        options.subject_id,
        options.tenant_id.map(str::to_owned),
    )?;
    let path = options.path;
    let store = ApiKeyStore::load_from_file(path)
        .with_context(|| format!("load API-key store {}", path.display()))?;
    let (key, raw_secret) = store.create_bound(
        options.prefix,
        options.scopes,
        Some(Duration::from_secs(options.ttl_seconds)),
        identity,
    )?;
    store
        .save_to_file(path)
        .with_context(|| format!("persist API-key store {}", path.display()))?;

    let result = json!({
        "id": key.id,
        "prefix": key.prefix,
        "raw_secret": raw_secret,
        "scopes": key.scopes,
        "identity": key.identity,
        "created_at": key.created_at,
        "expires_at": key.expires_at,
    });
    if output == "json" {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("API key created; copy the secret now (it will not be shown again):");
        println!("  id:      {}", key.id);
        println!(
            "  subject: {}::{}",
            options.subject_type, options.subject_id
        );
        println!("  scopes:  {}", key.scopes.join(", "));
        println!("  secret:  {raw_secret}");
    }
    Ok(())
}

pub fn list(path: impl AsRef<Path>, output: &str) -> Result<()> {
    let path = path.as_ref();
    let store = ApiKeyStore::load_from_file(path)
        .with_context(|| format!("load API-key store {}", path.display()))?;
    let mut keys = store.list();
    keys.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.id.cmp(&right.id))
    });
    let metadata: Vec<_> = keys
        .into_iter()
        .map(|key| {
            json!({
                "id": key.id,
                "prefix": key.prefix,
                "scopes": key.scopes,
                "identity": key.identity,
                "created_at": key.created_at,
                "expires_at": key.expires_at,
                "revoked_at": key.revoked_at,
            })
        })
        .collect();
    if output == "json" {
        println!("{}", serde_json::to_string_pretty(&metadata)?);
    } else if metadata.is_empty() {
        println!("No API keys in {}", path.display());
    } else {
        for key in metadata {
            let scopes = key["scopes"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|scope| scope.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            let identity = key["identity"]
                .as_object()
                .map(|identity| {
                    format!(
                        "{}::{}",
                        identity
                            .get("subject_type")
                            .and_then(|value| value.as_str())
                            .unwrap_or_default(),
                        identity
                            .get("subject_id")
                            .and_then(|value| value.as_str())
                            .unwrap_or_default(),
                    )
                })
                .unwrap_or_else(|| "unbound (legacy)".into());
            println!(
                "{}  {}  scopes={}  identity={}  status={}",
                key["id"].as_str().unwrap_or_default(),
                key["prefix"].as_str().unwrap_or_default(),
                scopes,
                identity,
                if key["revoked_at"].is_null() {
                    "active"
                } else {
                    "revoked"
                },
            );
        }
    }
    Ok(())
}

pub fn revoke(path: impl AsRef<Path>, id: &str, output: &str) -> Result<()> {
    let path = path.as_ref();
    let store = ApiKeyStore::load_from_file(path)
        .with_context(|| format!("load API-key store {}", path.display()))?;
    store
        .revoke(id)
        .with_context(|| format!("revoke API key {id}"))?;
    store
        .save_to_file(path)
        .with_context(|| format!("persist API-key store {}", path.display()))?;
    if output == "json" {
        println!("{}", json!({"id": id, "revoked": true}));
    } else {
        println!("Revoked API key {id}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_persists_bound_key_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        create(
            CreateKeyOptions {
                path: &path,
                prefix: "ag_test",
                subject_type: "Agent",
                subject_id: "research",
                tenant_id: Some("tenant-a"),
                scopes: vec!["authorize".into()],
                ttl_seconds: 3600,
            },
            "json",
        )
        .unwrap();
        let store = ApiKeyStore::load_from_file(&path).unwrap();
        let keys = store.list();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].identity.as_ref().unwrap().subject_id, "research");
        assert!(keys[0].has_scope("authorize"));
        assert_eq!(
            keys[0].identity.as_ref().unwrap().tenant_id.as_deref(),
            Some("tenant-a")
        );
    }

    #[test]
    fn create_rejects_invalid_identity_or_zero_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let options = |subject_type, ttl_seconds| CreateKeyOptions {
            path: &path,
            prefix: "ag_test",
            subject_type,
            subject_id: "alice",
            tenant_id: None,
            scopes: vec!["authorize".into()],
            ttl_seconds,
        };
        assert!(create(options("Service", 60), "json").is_err());
        assert!(create(options("User", 0), "json").is_err());
        assert!(!path.exists());
    }

    #[test]
    fn revoke_is_durable_and_unknown_id_does_not_rewrite_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let store = ApiKeyStore::new();
        let (key, _) = store
            .create_bound(
                "ag_test",
                vec!["authorize".into()],
                None,
                ApiKeyIdentity::new("User", "alice", None).unwrap(),
            )
            .unwrap();
        store.save_to_file(&path).unwrap();
        revoke(&path, &key.id, "json").unwrap();
        let reopened = ApiKeyStore::load_from_file(&path).unwrap();
        assert!(reopened.list()[0].revoked_at.is_some());
        let before = std::fs::read(&path).unwrap();
        assert!(revoke(&path, "missing", "json").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

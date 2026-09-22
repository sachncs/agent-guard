//! End-to-end integration tests for the agentguard CLI.
//!
//! These tests exercise the binary end-to-end: subprocess invocation, JSON
//! in/out, and policy validation. They catch regressions in the CLI wiring
//! that unit tests cannot.

use std::process::Command;

fn agentguard_bin() -> Command {
    let exe = env!("CARGO_BIN_EXE_agentguard");
    Command::new(exe)
}

#[test]
fn init_creates_store() {
    let dir = tempfile::tempdir().unwrap();
    let out = agentguard_bin()
        .args(["init", "--name", "test"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir
        .path()
        .join(".agentguard")
        .join("schema.cedarschema")
        .exists());
    assert!(dir.path().join(".agentguard").join("policies").exists());
}

#[test]
fn validate_passes_on_default_policies() {
    let dir = tempfile::tempdir().unwrap();
    agentguard_bin()
        .args(["init", "--name", "test"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let out = agentguard_bin()
        .args(["validate"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("no errors"), "got: {}", stdout);
}

#[test]
fn doctor_reports_ok() {
    let dir = tempfile::tempdir().unwrap();
    agentguard_bin()
        .args(["init", "--name", "test"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let out = agentguard_bin()
        .args(["doctor"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    // Doctor exits 0 on a healthy store. The chain secret is unset, which
    // is a warning (exit 2), but with no chain the store is still healthy
    // enough to pass the schema / policy / authorizer checks.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("schema"), "got: {}", stdout);
    assert!(stdout.contains("policies"), "got: {}", stdout);
    assert!(stdout.contains("audit log"), "got: {}", stdout);
    assert!(stdout.contains("authorizer"), "got: {}", stdout);
}

#[test]
fn apikey_cli_creates_lists_without_secret_and_revokes() {
    let dir = tempfile::tempdir().unwrap();
    let key_store = dir.path().join("keys.json");
    let key_store = key_store.to_str().unwrap();
    let created = agentguard_bin()
        .args([
            "--output",
            "json",
            "api-key",
            "create",
            "--key-store",
            key_store,
            "--subject-type",
            "Agent",
            "--subject-id",
            "research",
            "--tenant-id",
            "tenant-a",
            "--ttl-seconds",
            "3600",
        ])
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let id = payload["id"].as_str().unwrap();
    let raw_secret = payload["raw_secret"].as_str().unwrap();
    assert!(!raw_secret.is_empty());
    assert!(payload["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|scope| scope == "authorize"));
    assert_eq!(payload["identity"]["tenant_id"], "tenant-a");

    let listed = agentguard_bin()
        .args([
            "--output",
            "json",
            "api-key",
            "list",
            "--key-store",
            key_store,
        ])
        .output()
        .unwrap();
    assert!(listed.status.success());
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(!listing.contains(raw_secret));
    assert!(!listing.contains("secret_hash"));
    assert!(listing.contains(id));

    let revoked = agentguard_bin()
        .args([
            "--output",
            "json",
            "api-key",
            "revoke",
            "--key-store",
            key_store,
            id,
        ])
        .output()
        .unwrap();
    assert!(revoked.status.success());
    let listing_after_revoke = agentguard_bin()
        .args([
            "--output",
            "json",
            "api-key",
            "list",
            "--key-store",
            key_store,
        ])
        .output()
        .unwrap();
    assert!(listing_after_revoke.status.success());
    let keys: serde_json::Value = serde_json::from_slice(&listing_after_revoke.stdout).unwrap();
    assert!(!keys[0]["revoked_at"].is_null());
}

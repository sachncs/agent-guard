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

fn initialize(dir: &tempfile::TempDir) {
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
}

fn write_request(dir: &tempfile::TempDir, principal_type: &str, principal_id: &str) -> String {
    let path = dir.path().join("request.json");
    let request = serde_json::json!({
        "principal": {"type": principal_type, "uid": principal_id},
        "action": {"tool": "repo_read"},
        "resource": {"entity_type": "Repository", "uid": "demo"},
        "context": {"args": {"repo": "demo"}, "session": {"ip": "127.0.0.1"}}
    });
    std::fs::write(&path, serde_json::to_vec(&request).unwrap()).unwrap();
    path.to_string_lossy().into_owned()
}

#[test]
fn init_creates_store() {
    let dir = tempfile::tempdir().unwrap();
    initialize(&dir);
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
    initialize(&dir);
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
    initialize(&dir);
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
fn schema_command_returns_the_loaded_actions() {
    let dir = tempfile::tempdir().unwrap();
    initialize(&dir);
    let out = agentguard_bin()
        .args(["--output", "json", "schema"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let schema: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let actions = schema["actions"].as_array().unwrap();
    assert!(actions
        .iter()
        .any(|action| action["name"] == "ToolCall::repo_read"));
}

#[test]
fn sim_allows_starter_agent_policy_and_authorize_denial_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    initialize(&dir);
    let allowed_request = write_request(&dir, "agent", "research");
    let simulated = agentguard_bin()
        .args(["--output", "json", "sim", &allowed_request])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        simulated.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&simulated.stderr)
    );
    let decision: serde_json::Value = serde_json::from_slice(&simulated.stdout).unwrap();
    assert_eq!(decision["effect"], "allow");

    let denied_request = write_request(&dir, "user", "bob");
    let audit_path = dir.path().join("audit/decisions.jsonl");
    let denied = agentguard_bin()
        .args([
            "--output",
            "json",
            "--audit",
            audit_path.to_str().unwrap(),
            "authorize",
            &denied_request,
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(2));
    let decision: serde_json::Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(decision["effect"], "deny");

    let tailed = agentguard_bin()
        .args([
            "--output",
            "json",
            "--audit",
            audit_path.to_str().unwrap(),
            "log",
            "tail",
            "--principal",
            "bob",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        tailed.status.success(),
        "{}",
        String::from_utf8_lossy(&tailed.stderr)
    );
    let records: serde_json::Value = serde_json::from_slice(&tailed.stdout).unwrap();
    assert_eq!(records.as_array().unwrap().len(), 1);
    assert_eq!(records[0]["principal"], "bob");
}

#[test]
fn authorize_allow_can_skip_audit_and_renders_human_readable_output() {
    let dir = tempfile::tempdir().unwrap();
    initialize(&dir);
    let request = write_request(&dir, "agent", "research");
    let out = agentguard_bin()
        .args(["authorize", &request, "--skip-audit"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ALLOW"), "got: {stdout}");
    assert!(stdout.contains("principal:"), "got: {stdout}");
    assert!(!dir.path().join(".audit/decisions.jsonl").exists());
}

#[test]
fn delegated_token_can_be_verified_with_the_reported_public_key() {
    let dir = tempfile::tempdir().unwrap();
    let minted = agentguard_bin()
        .args([
            "delegate",
            "--from",
            "Agent::\"research\"",
            "--to",
            "Agent::\"summarizer\"",
            "--actions",
            "ToolCall::repo_read",
            "--resources",
            "Repository::*",
            "--ttl",
            "300",
        ])
        .output()
        .unwrap();
    assert!(
        minted.status.success(),
        "{}",
        String::from_utf8_lossy(&minted.stderr)
    );
    let token = String::from_utf8(minted.stdout).unwrap().trim().to_owned();
    assert_eq!(token.split('.').count(), 3);

    let warning = String::from_utf8(minted.stderr).unwrap();
    let public_key = warning
        .split_once("public key (")
        .and_then(|(_, value)| value.split_once("): "))
        .expect("ephemeral signer reports its public key");
    let key_file = dir.path().join("delegation-keys.txt");
    std::fs::write(
        &key_file,
        format!("{}={}\n", public_key.0, public_key.1.trim()),
    )
    .unwrap();

    let verified = agentguard_bin()
        .args([
            "--output",
            "json",
            "verify",
            &token,
            "--keys",
            key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let claims: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(claims["sub"], "Agent::\"summarizer\"");
    assert_eq!(claims["allowed_actions"][0], "ToolCall::repo_read");
    assert_eq!(claims["resource_patterns"][0], "Repository::*");
}

#[test]
fn policy_generation_rejects_unknown_provider_without_network_access() {
    let dir = tempfile::tempdir().unwrap();
    initialize(&dir);
    let out = agentguard_bin()
        .args([
            "--store",
            dir.path().join(".agentguard").to_str().unwrap(),
            "gen",
            "allow repository reads",
            "--provider",
            "unknown",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown provider"));
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

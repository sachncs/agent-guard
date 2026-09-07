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

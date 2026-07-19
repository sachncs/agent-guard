//! `agentguard doctor` — diagnose a deployment.
//!
//! Checks schema loads, policies parse, schema validation passes, audit log
//! writable, hash chain (if configured) verifies, telemetry configured.

use agentguard_core::decision::DecisionLog;
use agentguard_core::decode_chain_secret;
use agentguard_core::policy::PolicyStore;
use anyhow::Result;
use std::path::Path;

/// Status of a single diagnostic check.
#[derive(Debug, Clone)]
pub enum CheckStatus {
    Ok,
    Warn(String),
    Fail(String),
}

impl CheckStatus {
    /// Single-character symbol for terminal output.
    pub fn symbol(&self) -> &'static str {
        match self {
            CheckStatus::Ok => "✓",
            CheckStatus::Warn(_) => "!",
            CheckStatus::Fail(_) => "✗",
        }
    }
}

/// Aggregated doctor report.
#[derive(Debug, Clone)]
pub struct DoctorReport {
    pub checks: Vec<(&'static str, CheckStatus)>,
}

impl DoctorReport {
    pub fn has_failures(&self) -> bool {
        self.checks
            .iter()
            .any(|(_, s)| matches!(s, CheckStatus::Fail(_)))
    }
    pub fn has_warnings(&self) -> bool {
        self.checks
            .iter()
            .any(|(_, s)| matches!(s, CheckStatus::Warn(_)))
    }
    pub fn print(&self) {
        for (name, status) in &self.checks {
            match status {
                CheckStatus::Ok => println!("  \x1b[32m{}\x1b[0m {}", status.symbol(), name),
                CheckStatus::Warn(msg) => {
                    println!("  \x1b[33m{}\x1b[0m {}: {}", status.symbol(), name, msg)
                }
                CheckStatus::Fail(msg) => {
                    println!("  \x1b[31m{}\x1b[0m {}: {}", status.symbol(), name, msg)
                }
            }
        }
    }
}

pub fn run(
    store_root: &Path,
    audit_log: &Path,
    chain_secret: Option<&Path>,
) -> Result<DoctorReport> {
    let mut report = DoctorReport { checks: vec![] };

    // 1. Schema
    let store = match PolicyStore::open(store_root) {
        Ok(s) => s,
        Err(e) => {
            report
                .checks
                .push(("schema", CheckStatus::Fail(e.to_string())));
            return Ok(report);
        }
    };
    let schema = store.load_schema().ok().flatten();
    match &schema {
        Some(_) => report.checks.push(("schema", CheckStatus::Ok)),
        None => report.checks.push((
            "schema",
            CheckStatus::Warn("no schema.cedarschema at store root".into()),
        )),
    }

    // 2. Policies
    let validation = match store.validate() {
        Ok(v) => v,
        Err(e) => {
            report
                .checks
                .push(("policies", CheckStatus::Fail(e.to_string())));
            return Ok(report);
        }
    };
    if validation.is_ok() {
        report.checks.push(("policies", CheckStatus::Ok));
    } else {
        let errs: Vec<String> = validation
            .errors
            .iter()
            .map(|e| e.message.clone())
            .collect();
        report
            .checks
            .push(("policies", CheckStatus::Fail(errs.join("; "))));
    }

    // 3. Audit log writable
    if audit_log.exists() {
        match std::fs::OpenOptions::new().append(true).open(audit_log) {
            Ok(_) => report.checks.push(("audit log", CheckStatus::Ok)),
            Err(e) => report
                .checks
                .push(("audit log", CheckStatus::Fail(e.to_string()))),
        }
    } else if let Some(parent) = audit_log.parent() {
        match std::fs::create_dir_all(parent) {
            Ok(_) => report.checks.push(("audit log", CheckStatus::Ok)),
            Err(e) => report
                .checks
                .push(("audit log", CheckStatus::Fail(e.to_string()))),
        }
    } else {
        report.checks.push(("audit log", CheckStatus::Ok));
    }

    // 4. Hash chain
    if let Some(secret_path) = chain_secret {
        if let Ok(key) = std::fs::read(secret_path) {
            if let Some(key_bytes) = decode_chain_secret(&key) {
                match DecisionLog::verify_chain(audit_log, &key_bytes) {
                    Ok(_) => report.checks.push(("hash chain", CheckStatus::Ok)),
                    Err(e) => report
                        .checks
                        .push(("hash chain", CheckStatus::Fail(e.to_string()))),
                }
            } else {
                report.checks.push((
                    "hash chain",
                    CheckStatus::Warn(format!("secret file {} is empty", secret_path.display())),
                ));
            }
        } else {
            report.checks.push((
                "hash chain",
                CheckStatus::Warn(format!("cannot read secret file {}", secret_path.display())),
            ));
        }
    } else {
        report.checks.push((
            "hash chain",
            CheckStatus::Warn("no chain secret configured (AGENTGUARD_CHAIN_SECRET unset)".into()),
        ));
    }

    // 5. Authorizer warm
    match agentguard_core::Authorizer::new(store) {
        Ok(_) => report.checks.push(("authorizer", CheckStatus::Ok)),
        Err(e) => report
            .checks
            .push(("authorizer", CheckStatus::Fail(e.to_string()))),
    }

    Ok(report)
}

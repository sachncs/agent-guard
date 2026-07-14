//! Lower-level policy types: validation reports, sources, severity.

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct PolicySource {
    pub path: PathBuf,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub policy_count: usize,
    pub errors: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub policy: String,
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

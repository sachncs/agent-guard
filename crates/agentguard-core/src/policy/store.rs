//! Policy store: loads/saves/validates Cedar policies and schemas.

use crate::error::Result;
use crate::policy::types::{PolicySource, Severity, ValidationIssue, ValidationReport};
use crate::schema::SchemaParsed;
use cedar_policy::{Policy, PolicyId, PolicySet, ValidationMode, Validator};
use std::path::PathBuf;
use std::str::FromStr;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct PolicyStore {
    pub root: PathBuf,
}

impl PolicyStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        if !root.exists() {
            std::fs::create_dir_all(root.join("policies"))?;
        }
        Ok(Self { root })
    }

    pub fn default_root() -> PathBuf {
        PathBuf::from(".agentguard")
    }

    pub fn schema_path(&self) -> PathBuf {
        self.root.join("schema.cedarschema")
    }

    pub fn policies_dir(&self) -> PathBuf {
        self.root.join("policies")
    }

    pub fn load_policies(&self) -> Result<(PolicySet, Vec<PolicySource>)> {
        let mut set = PolicySet::new();
        let mut sources = Vec::new();
        let dir = self.policies_dir();

        if !dir.exists() {
            return Ok((set, sources));
        }

        for entry in WalkDir::new(&dir).sort_by_file_name() {
            let entry = entry.map_err(|e| crate::error::Error::Walk(e.to_string()))?;
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("cedar")
            {
                let src = std::fs::read_to_string(entry.path())?;
                let file_set =
                    PolicySet::from_str(&src).map_err(|e| crate::error::Error::PolicyParse {
                        message: e.to_string(),
                        file: src.clone(),
                    })?;
                set.merge(&file_set, true)
                    .map_err(|e| crate::error::Error::PolicyParse {
                        message: e.to_string(),
                        file: src.clone(),
                    })?;
                sources.push(PolicySource {
                    path: entry.path().to_path_buf(),
                    text: src,
                });
            }
        }

        Ok((set, sources))
    }

    pub fn load_schema(&self) -> Result<Option<SchemaParsed>> {
        let p = self.schema_path();
        if !p.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&p)?;
        let (schema, _warnings) = cedar_policy::Schema::from_cedarschema_str(&text)
            .map_err(|e| crate::error::Error::Schema(e.to_string()))?;
        Ok(Some(SchemaParsed {
            schema,
            source: text,
        }))
    }

    pub fn validate(&self) -> Result<ValidationReport> {
        let (policies, sources) = self.load_policies()?;
        let schema = self.load_schema()?;

        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        for src in &sources {
            let pid = PolicyId::new(src.path.to_string_lossy());
            if let Err(e) = Policy::parse(Some(pid), src.text.clone()) {
                errors.push(ValidationIssue {
                    policy: src.path.to_string_lossy().to_string(),
                    severity: Severity::Error,
                    message: e.to_string(),
                });
            }
        }

        if let Some(s) = &schema {
            let validator = Validator::new(s.schema.clone());
            let result = validator.validate(&policies, ValidationMode::Strict);
            for err in result.validation_errors() {
                errors.push(ValidationIssue {
                    policy: err.policy_id().to_string(),
                    severity: Severity::Error,
                    message: err.to_string(),
                });
            }
            for warn in result.validation_warnings() {
                warnings.push(ValidationIssue {
                    policy: warn.policy_id().to_string(),
                    severity: Severity::Warning,
                    message: warn.to_string(),
                });
            }
        } else {
            warnings.push(ValidationIssue {
                policy: "<store>".into(),
                severity: Severity::Warning,
                message: "no schema present; skipping type validation".into(),
            });
        }

        Ok(ValidationReport {
            policy_count: policies.policies().count(),
            errors,
            warnings,
        })
    }

    /// Write a policy file under `policies/`. `name` is sanitized to a
    /// single filename component: path separators and `..` segments are
    /// stripped, and the result is rejected if it would be empty or a
    /// parent-directory reference.
    pub fn write_policy(&self, name: &str, text: &str) -> Result<PathBuf> {
        // Strip path separators, NULs, and the like. We keep the
        // sanitization simple: anything that's not [A-Za-z0-9._-] is
        // replaced with '_'. This blocks '..' and '/'.
        let safe: String = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' })
            .collect();
        // Reject any name that, after sanitization, is empty or starts
        // with '.' (a hidden file or '.' / '..').
        if safe.is_empty() || safe.starts_with('.') {
            return Err(crate::error::Error::PolicyParse {
                message: format!("invalid policy name: {:?}", name),
                file: name.to_string(),
            });
        }
        let path = self.policies_dir().join(format!("{}.cedar", safe));
        // Defense in depth: confirm the resolved path stays inside the
        // policies directory (guards against symlink races).
        let policies_dir = self.policies_dir();
        let canonical_policies = std::fs::canonicalize(&policies_dir).unwrap_or(policies_dir);
        let resolved = path.clone();
        if let Ok(canonical) = std::fs::canonicalize(&resolved) {
            if !canonical.starts_with(&canonical_policies) {
                return Err(crate::error::Error::PolicyParse {
                    message: "policy path escapes policies dir".into(),
                    file: path.display().to_string(),
                });
            }
        }
        std::fs::create_dir_all(self.policies_dir())?;
        std::fs::write(&path, text)?;
        Ok(path)
    }

    pub fn write_schema(&self, text: &str) -> Result<()> {
        std::fs::write(self.schema_path(), text)?;
        Ok(())
    }
}

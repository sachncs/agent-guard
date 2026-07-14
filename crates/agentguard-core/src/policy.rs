//! Policy store: loads/saves/validates Cedar policies and schemas from disk.

use crate::error::{Error, Result};
use cedar_policy::{Policy, PolicyId, PolicySet, ValidationMode, Validator};
use std::path::{Path, PathBuf};
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
            let entry = entry.map_err(|e| Error::Walk(e.to_string()))?;
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("cedar")
            {
                let src = std::fs::read_to_string(entry.path())?;
                // Parse each file as a PolicySet (a file may contain multiple policies).
                let file_set = PolicySet::from_str(&src).map_err(|e| Error::PolicyParse {
                    message: e.to_string(),
                    file: src.clone(),
                })?;
                // Merge into the master set (in place).
                set.merge(&file_set, true).map_err(|e| Error::PolicyParse {
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

    pub fn load_schema(&self) -> Result<Option<crate::schema::SchemaParsed>> {
        let p = self.schema_path();
        if !p.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&p)?;
        let (schema, _warnings) = cedar_policy::Schema::from_cedarschema_str(&text)
            .map_err(|e| Error::Schema(e.to_string()))?;
        Ok(Some(crate::schema::SchemaParsed {
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
            let pid = PolicyId::new(src.path.to_string_lossy().to_string());
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

    pub fn write_policy(&self, name: &str, text: &str) -> Result<PathBuf> {
        let safe = name.replace(['/', '\\'], "_").replace("..", "_");
        let path = self.policies_dir().join(format!("{}.cedar", safe));
        std::fs::create_dir_all(self.policies_dir())?;
        std::fs::write(&path, text)?;
        Ok(path)
    }

    pub fn write_schema(&self, text: &str) -> Result<()> {
        std::fs::write(self.schema_path(), text)?;
        Ok(())
    }
}

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

pub fn init_store(root: impl AsRef<Path>) -> Result<()> {
    let store = PolicyStore::open(root.as_ref())?;
    let starter = include_str!("../../../schemas/starter.cedarschema");
    store.write_schema(starter)?;
    Ok(())
}

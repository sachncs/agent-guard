//! Policy store: loads/saves/validates Cedar policies and schemas.

use crate::error::Result;
use crate::policy::types::{PolicySource, Severity, ValidationIssue, ValidationReport};
use crate::schema::SchemaParsed;
use cedar_policy::{Policy, PolicyId, PolicySet, ValidationMode, Validator};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use walkdir::WalkDir;

const MAX_POLICY_FILES: usize = 1024;
const MAX_POLICY_TREE_ENTRIES: usize = 4096;
const MAX_POLICY_FILE_BYTES: u64 = 1_048_576;
const MAX_TOTAL_POLICY_BYTES: u64 = 16_777_216;
const MAX_SCHEMA_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone)]
pub struct PolicyStore {
    pub root: PathBuf,
}

impl PolicyStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
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

        let mut policy_count = 0usize;
        let mut total_bytes = 0u64;
        let mut entries_seen = 0usize;
        for entry in WalkDir::new(&dir) {
            let entry = entry.map_err(|e| crate::error::Error::Walk(e.to_string()))?;
            entries_seen += 1;
            if entries_seen > MAX_POLICY_TREE_ENTRIES {
                return Err(crate::error::Error::PolicyParse {
                    message: format!(
                        "policy store tree exceeds the limit of {MAX_POLICY_TREE_ENTRIES} entries"
                    ),
                    file: entry.path().display().to_string(),
                });
            }
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("cedar")
            {
                policy_count += 1;
                if policy_count > MAX_POLICY_FILES {
                    return Err(crate::error::Error::PolicyParse {
                        message: format!("policy count exceeds the limit of {MAX_POLICY_FILES}"),
                        file: entry.path().display().to_string(),
                    });
                }
                let src = read_bounded_text(entry.path(), MAX_POLICY_FILE_BYTES, "policy")?;
                total_bytes = total_bytes.checked_add(src.len() as u64).ok_or_else(|| {
                    crate::error::Error::PolicyParse {
                        message: "total policy source size overflow".into(),
                        file: entry.path().display().to_string(),
                    }
                })?;
                if total_bytes > MAX_TOTAL_POLICY_BYTES {
                    return Err(crate::error::Error::PolicyParse {
                        message: format!(
                            "total policy source size exceeds the limit of {MAX_TOTAL_POLICY_BYTES} bytes"
                        ),
                        file: entry.path().display().to_string(),
                    });
                }
                sources.push(PolicySource {
                    path: entry.path().to_path_buf(),
                    text: src,
                });
            }
        }

        // Parse only after the complete input set is within its bounds. This
        // prevents a directory with many large, valid prefix files from
        // allocating policy ASTs before the total-size cap is enforced.
        // Sort after the bounded walk to preserve deterministic source order
        // without buffering an unbounded directory for WalkDir's sorter.
        sources.sort_by(|left, right| left.path.cmp(&right.path));
        for src in &sources {
            let file_set =
                PolicySet::from_str(&src.text).map_err(|e| crate::error::Error::PolicyParse {
                    message: e.to_string(),
                    file: src.path.display().to_string(),
                })?;
            set.merge(&file_set, true)
                .map_err(|e| crate::error::Error::PolicyParse {
                    message: e.to_string(),
                    file: src.path.display().to_string(),
                })?;
        }

        Ok((set, sources))
    }

    pub fn load_schema(&self) -> Result<Option<SchemaParsed>> {
        let p = self.schema_path();
        if !p.exists() {
            return Ok(None);
        }
        let text = read_bounded_text(&p, MAX_SCHEMA_BYTES, "schema")?;
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
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
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

fn read_bounded_text(path: &Path, max_bytes: u64, label: &str) -> Result<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(crate::error::Error::Other(format!(
            "{} exceeds the {label} size limit of {max_bytes} bytes",
            path.display()
        )));
    }
    String::from_utf8(bytes).map_err(|error| {
        crate::error::Error::Other(format!("{} is not valid UTF-8: {error}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn policy_file_count_over_limit_fails_instead_of_silently_truncating() {
        let dir = tempdir().unwrap();
        let store = PolicyStore::open(dir.path()).unwrap();
        fs::create_dir_all(store.policies_dir()).unwrap();
        for index in 0..=MAX_POLICY_FILES {
            fs::write(store.policies_dir().join(format!("{index:04}.cedar")), "").unwrap();
        }

        let error = store.load_policies().unwrap_err();
        assert!(error.to_string().contains("policy count exceeds"));
    }

    #[test]
    fn policy_tree_entry_count_is_bounded() {
        let dir = tempdir().unwrap();
        let store = PolicyStore::open(dir.path()).unwrap();
        fs::create_dir_all(store.policies_dir()).unwrap();
        for index in 0..MAX_POLICY_TREE_ENTRIES {
            fs::write(
                store.policies_dir().join(format!("{index:04}.txt")),
                "ignored non-policy file",
            )
            .unwrap();
        }

        let error = store.load_policies().unwrap_err();
        assert!(error.to_string().contains("policy store tree exceeds"));
    }

    #[test]
    fn total_policy_source_size_is_bounded_before_policy_parsing() {
        let dir = tempdir().unwrap();
        let store = PolicyStore::open(dir.path()).unwrap();
        fs::create_dir_all(store.policies_dir()).unwrap();
        let comment = format!("// {}\n", "x".repeat(MAX_POLICY_FILE_BYTES as usize - 4));
        for index in 0..=MAX_TOTAL_POLICY_BYTES / MAX_POLICY_FILE_BYTES {
            fs::write(
                store.policies_dir().join(format!("{index:04}.cedar")),
                &comment,
            )
            .unwrap();
        }

        let error = store.load_policies().unwrap_err();
        assert!(error
            .to_string()
            .contains("total policy source size exceeds"));
    }

    #[test]
    fn individual_policy_file_size_is_bounded() {
        let dir = tempdir().unwrap();
        let store = PolicyStore::open(dir.path()).unwrap();
        fs::create_dir_all(store.policies_dir()).unwrap();
        fs::write(
            store.policies_dir().join("oversized.cedar"),
            vec![b'x'; MAX_POLICY_FILE_BYTES as usize + 1],
        )
        .unwrap();

        let error = store.load_policies().unwrap_err();
        assert!(error.to_string().contains("policy size limit"));
    }

    #[test]
    fn schema_size_is_bounded_before_schema_parsing() {
        let dir = tempdir().unwrap();
        let store = PolicyStore::open(dir.path()).unwrap();
        fs::write(
            store.schema_path(),
            vec![b'x'; MAX_SCHEMA_BYTES as usize + 1],
        )
        .unwrap();

        let error = store.load_schema().unwrap_err();
        assert!(error.to_string().contains("schema size limit"));
    }

    #[test]
    fn policy_directories_do_not_consume_the_policy_file_limit() {
        let dir = tempdir().unwrap();
        let store = PolicyStore::open(dir.path()).unwrap();
        let nested = store.policies_dir().join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            nested.join("allow.cedar"),
            "permit(principal, action, resource);",
        )
        .unwrap();

        let (policies, sources) = store.load_policies().unwrap();
        assert_eq!(policies.policies().count(), 1);
        assert_eq!(sources.len(), 1);
    }
}

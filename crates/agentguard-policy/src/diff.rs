//! Line-level diff between two [`PolicyBundle`]s.

use crate::PolicyBundle;

/// Compute a unified text diff between the two bundles' policy sources.
///
/// The result is a list of `(policy_id, line_diff)` pairs. Each `line_diff`
/// is the unified diff text (empty string if the policies are identical).
pub fn diff_bundles(old: &PolicyBundle, new: &PolicyBundle) -> Vec<(String, String)> {
    use std::collections::HashMap;
    let old_map: HashMap<&str, &str> = old
        .policies
        .iter()
        .map(|p| (p.id.as_str(), p.source.as_str()))
        .collect();
    let new_map: HashMap<&str, &str> = new
        .policies
        .iter()
        .map(|p| (p.id.as_str(), p.source.as_str()))
        .collect();

    let mut out: Vec<(String, String)> = Vec::new();

    // Removed policies.
    for id in old_map.keys() {
        if !new_map.contains_key(*id) {
            out.push(((*id).to_string(), line_diff(Some(""), Some(""))));
        }
    }
    // Added or changed policies.
    for (id, new_src) in &new_map {
        let old_src = old_map.get(id).copied();
        if old_src != Some(*new_src) {
            out.push(((*id).to_string(), line_diff(old_src, Some(new_src))));
        }
    }
    out
}

/// Unified text diff between two optional strings. Empty string if identical.
pub fn line_diff(old: Option<&str>, new: Option<&str>) -> String {
    use similar::{ChangeTag, TextDiff};
    let old = old.unwrap_or("");
    let new = new.unwrap_or("");
    let diff = TextDiff::from_lines(old, new);
    let mut out = String::new();
    for change in diff.iter_all_changes() {
        let prefix = match change.tag() {
            ChangeTag::Equal => " ",
            ChangeTag::Insert => "+",
            ChangeTag::Delete => "-",
        };
        out.push_str(prefix);
        out.push_str(change.value());
        if !change.value().ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::PolicyVersion;
    use crate::{NamedPolicy, PolicyBundle};

    fn bundle(id: &str, source: &str) -> PolicyBundle {
        PolicyBundle {
            version: PolicyVersion::new(1),
            tenant_id: "t".into(),
            schema_hash: [0u8; 32],
            policies_hash: [0u8; 32],
            created_at: 0,
            created_by: "test".into(),
            signature: None,
            schema_source: "entity User;".into(),
            policies: vec![NamedPolicy {
                id: id.into(),
                source: source.into(),
            }],
        }
    }

    #[test]
    fn unchanged_policies_produce_no_diff() {
        let b = bundle("p0", "permit (principal, action, resource);");
        let diff = diff_bundles(&b, &b);
        assert!(diff.is_empty(), "expected no diff, got {:?}", diff);
    }

    #[test]
    fn changed_policy_is_detected() {
        let a = bundle("p0", "permit (principal, action, resource);");
        let b = bundle("p0", "forbid (principal, action, resource);");
        let diff = diff_bundles(&a, &b);
        assert_eq!(diff.len(), 1);
        let (id, text) = &diff[0];
        assert_eq!(id, "p0");
        assert!(text.contains("-permit"));
        assert!(text.contains("+forbid"));
    }

    #[test]
    fn added_policy_is_detected() {
        let a = bundle("p0", "permit (principal, action, resource);");
        let mut b = bundle("p0", "permit (principal, action, resource);");
        b.policies
            .push(NamedPolicy { id: "p1".into(), source: "permit (...)".into() });
        let diff = diff_bundles(&a, &b);
        assert!(diff.iter().any(|(id, _)| id == "p1"));
    }
}
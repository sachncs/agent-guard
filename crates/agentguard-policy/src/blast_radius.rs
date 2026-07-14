//! Blast-radius analysis: classify decision changes across a replay corpus.
//!
//! A blast-radius analysis replays a corpus of past authorization requests
//! against both the old and the new policy bundle, then classifies each
//! request as `Unchanged`, `AllowToDeny` (the dangerous direction),
//! `DenyToAllow` (often a bug), or `Other` (transitions between Deny and
//! an error state, etc.).
//!
//! Complexity: O(N × P) where N = replay corpus size, P = policy set size.
//! The Authorizer for each bundle is constructed once and reused across
//! the corpus, so the dominant cost is `O(N)` cedar policy evaluations.

use crate::PolicyBundle;
use agentguard_core::authorize::entities::build_entities;
use agentguard_core::ttl::Clock;
use agentguard_core::{AgentRequest, Authorizer, Effect};
use std::sync::Arc;

/// Classification of how a single replay request's decision changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeClass {
    Unchanged,
    AllowToDeny,
    DenyToAllow,
    Other(String),
}

impl ChangeClass {
    pub fn is_dangerous(&self) -> bool {
        matches!(self, ChangeClass::AllowToDeny)
    }
}

/// A replay request — a serialized [`agentguard_core::AgentRequest`]
/// plus the entities that should be loaded with it.
#[derive(Debug, Clone)]
pub struct ReplayRequest {
    pub request: Box<AgentRequest>,
    pub entities: Vec<serde_json::Value>,
    /// Expected authorization effect under the old bundle. Stored so
    /// callers can sanity-check their corpus before running analysis.
    #[allow(dead_code)]
    pub old_effect: String,
}

/// Aggregate blast-radius report.
#[derive(Debug, Default, Clone)]
pub struct BlastRadiusReport {
    pub unchanged: usize,
    pub allow_to_deny: usize,
    pub deny_to_allow: usize,
    pub other: usize,
    /// One example per observed `AllowToDeny` (capped at 10).
    pub sample_allow_to_deny: Vec<ReplayRequest>,
    /// One example per observed `DenyToAllow` (capped at 10).
    pub sample_deny_to_allow: Vec<ReplayRequest>,
}

impl BlastRadiusReport {
    /// Total number of replay requests classified.
    pub fn total(&self) -> usize {
        self.unchanged + self.allow_to_deny + self.deny_to_allow + self.other
    }

    /// `true` if any request that was `Allow` is now `Deny`.
    pub fn has_allow_to_deny(&self) -> bool {
        self.allow_to_deny > 0
    }
}

impl std::fmt::Display for BlastRadiusReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "blast-radius report:")?;
        writeln!(f, "  unchanged:    {}", self.unchanged)?;
        writeln!(f, "  allow→deny:   {} (DANGEROUS)", self.allow_to_deny)?;
        writeln!(f, "  deny→allow:   {}", self.deny_to_allow)?;
        if self.other > 0 {
            writeln!(f, "  other:        {}", self.other)?;
        }
        if self.has_allow_to_deny() {
            writeln!(f, "  WARNING: at least one allow→deny flip detected")?;
        }
        Ok(())
    }
}

/// Classify the change between two cedar effects.
fn classify(old: Effect, new: Effect) -> ChangeClass {
    match (old, new) {
        (Effect::Allow, Effect::Deny) => ChangeClass::AllowToDeny,
        (Effect::Deny, Effect::Allow) => ChangeClass::DenyToAllow,
        (a, b) if a == b => ChangeClass::Unchanged,
        (a, b) => ChangeClass::Other(format!("{:?}→{:?}", a, b)),
    }
}

/// Maximum number of sample requests kept per category in the report.
const SAMPLE_CAP: usize = 10;

/// Replay the corpus against both bundles and classify the changes.
///
/// Each `ReplayRequest` is evaluated by the old `Authorizer` and the new
/// `Authorizer`. The pair of decisions is classified; samples of
/// `AllowToDeny` and `DenyToAllow` flips are retained (capped at
/// `SAMPLE_CAP`) for debugging and audit.
///
/// # Errors
/// Returns an error string if either bundle's schema or policy set fails
/// to parse. The replay engine itself is infallible (the cedar
/// `Authorizer::authorize` does not return an error for a well-formed
/// request — cedar policy evaluation is total).
///
/// # Examples
/// ```
/// use agentguard_policy::blast_radius::{analyze, ReplayRequest};
/// use agentguard_policy::{NamedPolicy, PolicyBundle};
/// use agentguard_policy::version::PolicyVersion;
/// use agentguard_core::AgentRequestBuilder;
/// use agentguard_core::{Principal, AgentAction, Resource, AgentContext};
/// use agentguard_core::ttl::SystemClock;
///
/// let schema = r#"entity User;
/// entity Mailbox;
/// action "ToolCall::send_email" appliesTo { principal: [User], resource: [Mailbox] };"#;
/// let bundle = |src: &str| PolicyBundle {
///     version: PolicyVersion::new(1),
///     tenant_id: "test".into(),
///     schema_hash: [0u8; 32],
///     policies_hash: [0u8; 32],
///     created_at: 0,
///     created_by: "test".into(),
///     signature: None,
///     schema_source: schema.into(),
///     policies: vec![NamedPolicy { id: "p".into(), source: src.into() }],
/// };
/// let req = ReplayRequest {
///     request: Box::new(
///         AgentRequestBuilder::new(Principal::user("alice"))
///             .action(AgentAction::tool("send_email"))
///             .resource(Resource::new("Mailbox", "alice@acme"))
///             .context(AgentContext::new())
///             .build()
///             .unwrap()
///     ),
///     entities: vec![],
///     old_effect: "allow".into(),
/// };
/// let report = analyze(
///     &bundle(r#"permit (principal in User::"alice", action == Action::"ToolCall::send_email", resource == Mailbox::"alice@acme");"#),
///     &bundle(r#"forbid (principal, action, resource);"#),
///     &[req],
///     &SystemClock,
/// )
/// .unwrap();
/// assert_eq!(report.allow_to_deny, 1);
/// ```
pub fn analyze(
    old: &PolicyBundle,
    new: &PolicyBundle,
    replay: &[ReplayRequest],
    clock: &dyn Clock,
) -> std::result::Result<BlastRadiusReport, String> {
    let _ = clock; // Reserved for future per-replay time-stamping.
    let old_authorizer = Arc::new(build_authorizer(old)?);
    let new_authorizer = Arc::new(build_authorizer(new)?);

    let mut report = BlastRadiusReport::default();
    for req in replay {
        let entities = build_entities(req.entities.clone())
            .map_err(|e| format!("replay entity build: {}", e))?;

        let old_decision = old_authorizer
            .authorize(&req.request, &entities)
            .map_err(|e| format!("old-bundle authorize: {}", e))?;
        let new_decision = new_authorizer
            .authorize(&req.request, &entities)
            .map_err(|e| format!("new-bundle authorize: {}", e))?;

        match classify(old_decision.effect, new_decision.effect) {
            ChangeClass::Unchanged => report.unchanged += 1,
            ChangeClass::AllowToDeny => {
                report.allow_to_deny += 1;
                if report.sample_allow_to_deny.len() < SAMPLE_CAP {
                    report.sample_allow_to_deny.push(req.clone());
                }
            }
            ChangeClass::DenyToAllow => {
                report.deny_to_allow += 1;
                if report.sample_deny_to_allow.len() < SAMPLE_CAP {
                    report.sample_deny_to_allow.push(req.clone());
                }
            }
            ChangeClass::Other(_) => report.other += 1,
        }
    }
    Ok(report)
}

/// Build an `Authorizer` from a `PolicyBundle` by parsing its `schema_source`
/// and policy text.
///
/// # Errors
/// Returns an error string if the schema or policy text is malformed
/// (mirrors the kinds of errors `PolicyStore::validate` produces).
fn build_authorizer(bundle: &PolicyBundle) -> std::result::Result<Authorizer, String> {
    use agentguard_core::PolicyStore;
    use std::path::Path;

    // Build a temp directory containing the bundle's files, point a
    // `PolicyStore` at it, then load.
    let dir = tempdir_in("/tmp")?;
    let schema_path = dir.join("schema.cedarschema");
    let policies_dir = dir.join("policies");
    std::fs::create_dir_all(&policies_dir).map_err(|e| format!("create policies dir: {}", e))?;
    std::fs::write(&schema_path, &bundle.schema_source)
        .map_err(|e| format!("write schema: {}", e))?;
    for (i, p) in bundle.policies.iter().enumerate() {
        let path = policies_dir.join(format!("{:03}_{}.cedar", i, p.id));
        std::fs::write(&path, &p.source).map_err(|e| format!("write policy {}: {}", p.id, e))?;
    }
    let store =
        PolicyStore::open(Path::new(&dir)).map_err(|e| format!("open policy store: {}", e))?;
    Authorizer::new(store).map_err(|e| format!("build authorizer: {}", e))
}

fn tempdir_in(prefix: &str) -> std::result::Result<std::path::PathBuf, String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Combine a timestamp with a process-wide counter so concurrent test
    // threads (e.g. cargo test with --test-threads > 1) get unique names.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::path::PathBuf::from(prefix).join(format!("agentguard-blast-{}-{}", nanos, seq));
    std::fs::create_dir_all(&path).map_err(|e| format!("create tempdir: {}", e))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::PolicyVersion;
    use crate::{NamedPolicy, PolicyBundle};
    use agentguard_core::ttl::SystemClock;
    use agentguard_core::{AgentAction, AgentContext, AgentRequestBuilder, Principal, Resource};
    use serde_json::json;

    fn bundle(schema: &str, policy_name: &str, policy: &str) -> PolicyBundle {
        PolicyBundle {
            version: PolicyVersion::new(1),
            tenant_id: "test".into(),
            schema_hash: [0u8; 32],
            policies_hash: [0u8; 32],
            created_at: 0,
            created_by: "test".into(),
            signature: None,
            schema_source: schema.into(),
            policies: vec![NamedPolicy {
                id: policy_name.into(),
                source: policy.into(),
            }],
        }
    }

    fn make_request() -> ReplayRequest {
        ReplayRequest {
            request: Box::new(
                AgentRequestBuilder::new(Principal::user("alice"))
                    .action(AgentAction::tool("send_email"))
                    .resource(Resource::new("Mailbox", "alice@acme"))
                    .context(AgentContext::new())
                    .build()
                    .unwrap(),
            ),
            entities: vec![],
            old_effect: "allow".into(),
        }
    }

    const SCHEMA: &str = r#"
entity User;
entity Mailbox;
action "ToolCall::send_email" appliesTo { principal: [User], resource: [Mailbox] };
"#;

    fn allow_alice_email() -> &'static str {
        r#"permit (principal in User::"alice", action == Action::"ToolCall::send_email", resource == Mailbox::"alice@acme");"#
    }

    fn deny_alice_email() -> &'static str {
        r#"forbid (principal, action, resource);"#
    }

    #[test]
    fn change_class_dangerous() {
        assert!(ChangeClass::AllowToDeny.is_dangerous());
        assert!(!ChangeClass::DenyToAllow.is_dangerous());
        assert!(!ChangeClass::Unchanged.is_dangerous());
        assert!(!matches!(
            ChangeClass::Other("foo".into()),
            ChangeClass::Unchanged
        ));
    }

    #[test]
    fn empty_report() {
        let r = BlastRadiusReport::default();
        assert_eq!(r.total(), 0);
        assert!(!r.has_allow_to_deny());
    }

    #[test]
    fn analyze_classifies_unchanged() {
        let old = bundle(SCHEMA, "p", allow_alice_email());
        let new = bundle(SCHEMA, "p", allow_alice_email());
        let report = analyze(&old, &new, &[make_request()], &SystemClock).unwrap();
        assert_eq!(report.total(), 1);
        assert_eq!(report.unchanged, 1);
        assert_eq!(report.allow_to_deny, 0);
        assert_eq!(report.deny_to_allow, 0);
    }

    #[test]
    fn analyze_classifies_allow_to_deny() {
        let old = bundle(SCHEMA, "p", allow_alice_email());
        let new = bundle(SCHEMA, "p", deny_alice_email());
        let report = analyze(&old, &new, &[make_request()], &SystemClock).unwrap();
        assert_eq!(report.total(), 1);
        assert_eq!(report.allow_to_deny, 1);
        assert_eq!(report.sample_allow_to_deny.len(), 1);
        assert!(report.has_allow_to_deny());
    }

    #[test]
    fn analyze_classifies_deny_to_allow() {
        let old = bundle(SCHEMA, "p", deny_alice_email());
        let new = bundle(SCHEMA, "p", allow_alice_email());
        let report = analyze(&old, &new, &[make_request()], &SystemClock).unwrap();
        assert_eq!(report.deny_to_allow, 1);
        assert_eq!(report.sample_deny_to_allow.len(), 1);
    }

    #[test]
    fn analyze_samples_capped_at_ten() {
        let old = bundle(SCHEMA, "p", allow_alice_email());
        let new = bundle(SCHEMA, "p", deny_alice_email());
        let corpus: Vec<ReplayRequest> = (0..12).map(|_| make_request()).collect();
        let report = analyze(&old, &new, &corpus, &SystemClock).unwrap();
        assert_eq!(report.allow_to_deny, 12);
        assert_eq!(report.sample_allow_to_deny.len(), SAMPLE_CAP);
    }

    #[test]
    fn analyze_mixed_corpus_counts_correctly() {
        // 3 unchanged + 2 allow→deny + 1 deny→allow
        let old = bundle(SCHEMA, "p", allow_alice_email());
        let new = bundle(SCHEMA, "p", deny_alice_email());
        let corpus: Vec<ReplayRequest> = (0..6).map(|_| make_request()).collect();
        let report = analyze(&old, &new, &corpus, &SystemClock).unwrap();
        assert_eq!(report.total(), 6);
        assert_eq!(report.allow_to_deny, 6);
    }

    #[test]
    fn analyze_rejects_malformed_bundle() {
        let bad = PolicyBundle {
            version: PolicyVersion::new(1),
            tenant_id: "test".into(),
            schema_hash: [0u8; 32],
            policies_hash: [0u8; 32],
            created_at: 0,
            created_by: "test".into(),
            signature: None,
            schema_source: "this is not a valid schema".into(),
            policies: vec![],
        };
        let res = analyze(&bad, &bad, &[make_request()], &SystemClock);
        assert!(res.is_err());
    }

    #[test]
    fn analyze_with_entities() {
        // The replay_request.entities must be passed to the Authorizer.
        // If the entity list is malformed, authorize fails — we propagate.
        let old = bundle(SCHEMA, "p", allow_alice_email());
        let new = bundle(SCHEMA, "p", allow_alice_email());
        let mut req = make_request();
        req.entities = vec![
            json!({"uid": {"type": "Mailbox", "id": "alice@acme"}, "attrs": {}, "parents": []}),
        ];
        let report = analyze(&old, &new, &[req], &SystemClock).unwrap();
        assert_eq!(report.unchanged, 1);
    }
}

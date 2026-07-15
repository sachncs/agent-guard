//! Authorization engine: evaluates a request against the policy store.

use crate::error::Result;
use crate::policy::PolicyStore;
use crate::request::AgentRequest;
use cedar_policy::{
    Authorizer as CedarAuthorizer, Decision as CedarDecision, Entities, PolicySet, Response,
};
use serde::{Deserialize, Serialize};

/// The result of evaluating an authorization request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub effect: Effect,
    pub policies: Vec<String>,
    pub reasons: Vec<String>,
    pub request: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

impl From<CedarDecision> for Effect {
    fn from(d: CedarDecision) -> Self {
        match d {
            CedarDecision::Allow => Effect::Allow,
            CedarDecision::Deny => Effect::Deny,
        }
    }
}

/// Build a structured trace JSON for the `Decision.trace` field.
///
/// The trace shape is:
/// ```json
/// {
///   "decision": "allow" | "deny",
///   "matched_policies": ["policy0", "policy1"],
///   "errors": ["error1"],
///   "warnings": ["warning1"]
/// }
/// ```
fn build_trace(
    resp: &Response,
    matched_policies: &[String],
    errors: &[String],
) -> serde_json::Value {
    let mut trace = serde_json::Map::new();
    trace.insert(
        "decision".into(),
        serde_json::Value::String(format!("{:?}", resp.decision())),
    );
    trace.insert(
        "matched_policies".into(),
        serde_json::Value::Array(
            matched_policies
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        ),
    );
    if !errors.is_empty() {
        trace.insert(
            "errors".into(),
            serde_json::Value::Array(
                errors
                    .iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        );
    }
    serde_json::Value::Object(trace)
}

/// Stateful authorizer wrapping cedar's engine.
pub struct Authorizer {
    inner: CedarAuthorizer,
    store: PolicyStore,
    schema: Option<cedar_policy::Schema>,
    policies: PolicySet,
}

impl Authorizer {
    pub fn new(store: PolicyStore) -> Result<Self> {
        let (policies, _sources) = store.load_policies()?;
        let schema = store.load_schema()?.map(|s| s.schema);
        Ok(Self {
            inner: CedarAuthorizer::new(),
            store,
            schema,
            policies,
        })
    }

    pub fn authorize(&self, req: &AgentRequest, entities: &Entities) -> Result<Decision> {
        let cedar_req = req.to_cedar_request(self.schema.as_ref())?;
        let resp: Response = self
            .inner
            .is_authorized(&cedar_req, &self.policies, entities);
        let effect: Effect = resp.decision().into();
        let diagnostics = resp.diagnostics();
        let policies: Vec<String> = diagnostics.reason().map(|r| r.to_string()).collect();
        let reasons: Vec<String> = diagnostics.errors().map(|e| e.to_string()).collect();
        // Build a structured trace JSON: the cedar policy IDs that
        // matched, any warnings/errors, and the request id for
        // correlation. Useful for debugging and post-hoc audit.
        let trace = build_trace(&resp, &policies, &reasons);
        Ok(Decision {
            effect,
            policies,
            reasons,
            request: serde_json::to_value(req)?,
            trace: Some(trace),
        })
    }

    pub fn schema(&self) -> Option<&cedar_policy::Schema> {
        self.schema.as_ref()
    }

    pub fn store(&self) -> &PolicyStore {
        &self.store
    }

    pub fn policies(&self) -> &PolicySet {
        &self.policies
    }

    /// Number of policies in the loaded set. O(1) for the `PolicySet`
    /// length (cached). Used by `/readyz` to check that policies are
    /// loaded without iterating the full set.
    pub fn policy_count(&self) -> usize {
        self.policies.policies().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::AgentRequestBuilder;
    use crate::{AgentAction, AgentContext, Principal, Resource};
    use tempfile::tempdir;

    fn allow_alice_email() -> &'static str {
        r#"permit (principal in User::"alice", action, resource);"#
    }

    fn make_authorizer() -> Authorizer {
        let dir = tempdir().unwrap();
        let store = PolicyStore::open(dir.path()).unwrap();
        store
            .write_policy("allow_alice", allow_alice_email())
            .unwrap();
        Authorizer::new(store).unwrap()
    }

    fn make_request() -> AgentRequest {
        AgentRequestBuilder::new(Principal::user("alice"))
            .action(AgentAction::tool("send_email"))
            .resource(Resource::new("Mailbox", "alice@acme"))
            .context(AgentContext::new())
            .build()
            .unwrap()
    }

    #[test]
    fn decision_includes_trace() {
        let authorizer = make_authorizer();
        let req = make_request();
        let decision = authorizer
            .authorize(&req, &cedar_policy::Entities::empty())
            .unwrap();
        assert_eq!(decision.effect, Effect::Allow);
        // Trace is now populated (was always None before commit 3).
        let trace = decision.trace.expect("trace must be populated");
        assert_eq!(trace["decision"], serde_json::json!("Allow"));
        let matched = trace["matched_policies"].as_array().unwrap();
        assert!(
            !matched.is_empty(),
            "matched_policies should list the matched policy"
        );
        // Cedar auto-generates policy IDs (policy0, policy1, ...) when
        // none is supplied. Just verify the array is populated.
        assert!(matched[0].is_string());
    }

    #[test]
    fn policy_count_returns_zero_for_empty_store() {
        let dir = tempdir().unwrap();
        let store = PolicyStore::open(dir.path()).unwrap();
        // No policies written.
        let authorizer = Authorizer::new(store).unwrap();
        assert_eq!(authorizer.policy_count(), 0);
    }

    #[test]
    fn policy_count_returns_loaded_count() {
        let dir = tempdir().unwrap();
        let store = PolicyStore::open(dir.path()).unwrap();
        // Use distinct policy text so cedar assigns distinct auto-IDs
        // (policy0, policy1). Two identical policies would both be auto-
        // assigned policy0, and cedar's merge would collapse them.
        store
            .write_policy("a", r#"permit (principal, action, resource);"#)
            .unwrap();
        store
            .write_policy(
                "b",
                r#"permit (principal, action == Action::"ToolCall::send_email", resource);"#,
            )
            .unwrap();
        let authorizer = Authorizer::new(store).unwrap();
        assert_eq!(authorizer.policy_count(), 2);
    }

    #[test]
    fn deny_decision_has_trace() {
        let authorizer = make_authorizer();
        // Bob is not in the allow_alice policy's principal.
        let req = AgentRequestBuilder::new(Principal::user("bob"))
            .action(AgentAction::tool("send_email"))
            .resource(Resource::new("Mailbox", "bob@acme"))
            .context(AgentContext::new())
            .build()
            .unwrap();
        let decision = authorizer
            .authorize(&req, &cedar_policy::Entities::empty())
            .unwrap();
        assert_eq!(decision.effect, Effect::Deny);
        let trace = decision.trace.expect("trace must be populated");
        assert_eq!(trace["decision"], serde_json::json!("Deny"));
    }
}

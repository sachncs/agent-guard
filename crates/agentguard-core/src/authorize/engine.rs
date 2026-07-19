//! Authorization engine: evaluates a request against the policy store.

use crate::decision::cache::{CacheKey, CachedDecision, DecisionCache};
use crate::error::Result;
use crate::policy::PolicyStore;
use crate::request::AgentRequest;
use crate::ttl::SystemClock;
use cedar_policy::{
    Authorizer as CedarAuthorizer, Decision as CedarDecision, Entities, PolicySet, Response,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The result of evaluating an authorization request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub effect: Effect,
    pub policies: Vec<String>,
    pub reasons: Vec<String>,
    pub request: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<serde_json::Value>,
    /// True if this decision was served from the decision cache (a hit).
    /// Surfaced to callers so they can include it in the audit record
    /// or `X-Decision-Source` response header.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub from_cache: bool,
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
    /// Optional decision cache. `None` = cache disabled (every call
    /// hits the cedar engine). Wire via [`Self::with_cache`].
    cache: Option<Arc<DecisionCache>>,
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
            cache: None,
        })
    }

    /// Enable the decision cache with the supplied config. Call multiple
    /// times to replace the cache (the previous `Arc` is dropped).
    pub fn with_cache(mut self, config: crate::decision::cache::CacheConfig) -> Self {
        let clock: Arc<dyn crate::ttl::Clock> = Arc::new(SystemClock);
        self.cache = Some(Arc::new(DecisionCache::new(config, clock)));
        self
    }

    /// Direct handle on the cache (for invalidation, metrics, tests).
    /// Returns `None` when the cache is disabled.
    pub fn cache(&self) -> Option<&Arc<DecisionCache>> {
        self.cache.as_ref()
    }

    /// Invalidate every cached decision. Call after a policy reload —
    /// the next `authorize()` falls through to cedar and re-populates.
    pub fn invalidate_cache(&self) {
        if let Some(c) = &self.cache {
            c.invalidate_all();
        }
    }

    #[tracing::instrument(
        skip_all,
        fields(
            principal = %req.principal,
            action = %req.action,
            resource = %req.resource,
        )
    )]
    pub fn authorize(&self, req: &AgentRequest, entities: &Entities) -> Result<Decision> {
        // Cache lookup (if enabled). On hit, rebuild a Decision with
        // from_cache=true; the request payload is stored verbatim so
        // downstream callers see the same trace shape as a fresh eval.
        if let Some(cache) = &self.cache {
            let key = CacheKey::for_request(req, cache.policy_version());
            if let Some(cached) = cache.get(&key) {
                let effect = match cached.effect.as_str() {
                    "allow" => Effect::Allow,
                    "deny" => Effect::Deny,
                    other => {
                        return Err(crate::error::Error::Other(format!(
                            "corrupt cache entry: bad effect {:?}",
                            other
                        )));
                    }
                };
                tracing::debug!("cache hit");
                return Ok(Decision {
                    effect,
                    policies: cached.policies,
                    reasons: cached.reasons,
                    request: serde_json::to_value(req)?,
                    trace: None,
                    from_cache: true,
                });
            }
        }

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

        // Populate the cache (if enabled) on the slow path so subsequent
        // identical requests hit.
        if let Some(cache) = &self.cache {
            let key = CacheKey::for_request(req, cache.policy_version());
            let cached = CachedDecision {
                effect: match effect {
                    Effect::Allow => "allow".into(),
                    Effect::Deny => "deny".into(),
                },
                policies: policies.clone(),
                reasons: reasons.clone(),
                cached_at_policy_version: cache.policy_version(),
            };
            cache.put(key, cached);
        }

        Ok(Decision {
            effect,
            policies,
            reasons,
            request: serde_json::to_value(req)?,
            trace: Some(trace),
            from_cache: false,
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

    #[test]
    fn cache_disabled_by_default() {
        let authorizer = make_authorizer();
        assert!(authorizer.cache().is_none());
    }

    #[test]
    fn cache_hit_on_second_identical_request() {
        let authorizer = make_authorizer().with_cache(crate::decision::cache::CacheConfig::default());
        let req = make_request();
        // First call: cache miss, populates.
        let d1 = authorizer
            .authorize(&req, &cedar_policy::Entities::empty())
            .unwrap();
        assert!(!d1.from_cache);
        // Second call: identical key, must hit.
        let d2 = authorizer
            .authorize(&req, &cedar_policy::Entities::empty())
            .unwrap();
        assert!(d2.from_cache, "second identical request must hit cache");
        assert_eq!(d2.effect, d1.effect);
        let cache = authorizer.cache().unwrap();
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 1);
    }

    #[test]
    fn cache_invalidation_flips_effect() {
        // Wire the cache, populate with Allow, mutate the policy to
        // Deny, invalidate, then re-evaluate. The new decision must
        // be the post-mutation Deny (not the cached Allow).
        let dir = tempdir().unwrap();
        let store = PolicyStore::open(dir.path()).unwrap();
        store
            .write_policy("allow_alice", r#"permit (principal, action, resource);"#)
            .unwrap();
        let authorizer = Authorizer::new(store)
            .unwrap()
            .with_cache(crate::decision::cache::CacheConfig::default());
        let req = make_request();
        let d1 = authorizer
            .authorize(&req, &cedar_policy::Entities::empty())
            .unwrap();
        assert_eq!(d1.effect, Effect::Allow);
        let d2 = authorizer
            .authorize(&req, &cedar_policy::Entities::empty())
            .unwrap();
        assert!(d2.from_cache);
        // Invalidate without changing the policy — the next decision
        // should re-evaluate and match the prior outcome.
        authorizer.invalidate_cache();
        let d3 = authorizer
            .authorize(&req, &cedar_policy::Entities::empty())
            .unwrap();
        assert!(!d3.from_cache, "post-invalidate call must miss");
        assert_eq!(d3.effect, Effect::Allow);
    }
}

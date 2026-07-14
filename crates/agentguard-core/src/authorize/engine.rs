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
        let policies: Vec<String> = resp.diagnostics().reason().map(|r| r.to_string()).collect();
        let reasons: Vec<String> = resp.diagnostics().errors().map(|e| e.to_string()).collect();
        Ok(Decision {
            effect,
            policies,
            reasons,
            request: serde_json::to_value(req)?,
            trace: None,
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
}

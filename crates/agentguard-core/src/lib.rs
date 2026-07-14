//! agentguard-core: Cedar-powered authorization primitives for AI agents.

pub mod action;
pub mod authorize;
pub mod context;
pub mod decision;
pub mod delegation;
pub mod error;
pub mod ids;
pub mod policy;
pub mod principal;
pub mod request;
pub mod resource;
pub mod schema;
pub mod simulate;

pub use action::AgentAction;
pub use authorize::{Authorizer, Decision, Effect};
pub use context::AgentContext;
pub use decision::{DecisionLog, DecisionRecord};
pub use delegation::{
    DelegationClaims, DelegationConfig, DelegationSigner, DelegationToken, DelegationVerifier,
};
pub use error::{Error, Result};
pub use ids::{ActionId, PrincipalId, ResourceId};
pub use policy::{init_store, PolicyStore, ValidationReport};
pub use principal::Principal;
pub use request::{AgentRequest, AgentRequestBuilder};
pub use resource::Resource;
pub use schema::{describe, SchemaSummary};

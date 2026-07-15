//! agentguard-core: Cedar-powered authorization primitives for AI agents.

pub mod action;
pub mod authorize;
pub mod context;
pub mod decision;
pub mod delegation;
pub mod error;
pub mod ids;
pub mod observability;
pub mod policy;
pub mod principal;
pub mod request;
pub mod resource;
pub mod schema;
pub mod ttl;

pub use action::AgentAction;
pub use authorize::{Authorizer, Decision, Effect};
pub use context::AgentContext;
pub use decision::{DecisionCache, DecisionLog, DecisionRecord};
pub use delegation::{
    DelegationClaims, DelegationConfig, DelegationSigner, DelegationToken, DelegationVerifier,
};
pub use error::{Error, Result};
pub use ids::{ActionId, PrincipalId, ResourceId};
pub use observability::{SpanId, TraceContext, TraceId};
pub use policy::{
    init_store, PolicySource, PolicyStore, Severity, ValidationIssue, ValidationReport,
};
pub use principal::Principal;
pub use request::{AgentRequest, AgentRequestBuilder};
pub use resource::Resource;
pub use schema::{describe, SchemaSummary};
pub use ttl::{Clock, MockClock, SystemClock, Timestamp};

//! agentguard-core: Cedar-powered authorization primitives for AI agents.

pub mod authorize;
pub mod decision;
pub mod delegation;
pub mod error;
pub mod policy;
pub mod request;
pub mod schema;
pub mod simulate;

pub use error::{Error, Result};
pub use policy::{init_store, PolicyStore, ValidationReport};
pub use request::{ActionDef, AgentAction, AgentContext, AgentRequest, Principal, Resource};
pub use authorize::{Authorizer, Decision, Effect};
pub use delegation::{DelegationClaims, DelegationConfig, DelegationSigner, DelegationToken, DelegationVerifier};
pub use decision::{DecisionLog, DecisionRecord};
pub use schema::{describe, SchemaSummary};
pub use simulate::{SimulationResult, Simulator};
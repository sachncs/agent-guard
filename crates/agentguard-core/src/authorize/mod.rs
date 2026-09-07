//! Authorization engine: evaluates a request against the policy store.

pub mod engine;
pub mod entities;

pub use engine::{Authorizer, Decision, Effect};
pub use entities::build_entities;

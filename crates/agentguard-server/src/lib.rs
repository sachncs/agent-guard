//! `agentguard serve` — AuthZEN HTTP + gRPC PDP.
//!
//! Embedders can mount the AuthZEN HTTP surface inside an existing axum
//! app via [`build_router`], or run it as a standalone service via
//! [`run`]. The request-shape helpers ([`evaluation_request_to_agent`],
//! [`build_request_entities`]) and the [`MAX_BATCH_EVALUATIONS`] budget
//! are re-exported for downstream consumers that want to keep request
//! shaping aligned with the PDP's expectations.
//!
//! See `docs/internal/stages/STAGE-7-server.md` for the full
//! implementation plan and `docs/architecture.md` for the canonical
//! embedder-surface documentation.

pub mod auth_layer;
pub mod authzen;
pub mod grpc;
pub mod listener;
pub mod proto;
pub mod server;

pub use auth_layer::AuthLayer;
pub use authzen::{
    build_request_entities, evaluation_request_to_agent, AppState, MAX_BATCH_EVALUATIONS,
};
pub use listener::{AuthConfig, ServerConfig};
pub use server::{build_router, run};

//! `agentguard serve` — AuthZEN HTTP + gRPC PDP.
//!
//! See `stages/STAGE-7-server.md` for the full implementation plan.

pub mod auth_layer;
pub mod authzen;
pub mod grpc;
pub mod listener;
pub mod proto;
pub mod server;

pub use auth_layer::AuthLayer;
pub use authzen::AppState;
pub use listener::{AuthConfig, ServerConfig};
pub use server::run;

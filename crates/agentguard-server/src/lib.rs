//! `agentguard serve` — AuthZEN HTTP + gRPC PDP.
//!
//! See `stages/STAGE-7-server.md` for the full implementation plan.

pub mod authzen;
pub mod listener;
pub mod server;

pub use authzen::AppState;
pub use listener::ServerConfig;
pub use server::run;

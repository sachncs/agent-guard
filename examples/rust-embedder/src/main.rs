//! Rust embedder example for agentguard-server.
//!
//! Shows how to mount the AuthZEN PDP router inside an existing axum
//! app via `agentguard_server::build_router`. The application keeps
//! its own `/healthz` and `/version` routes; the agentguard router is
//! nested under `/access/v1` so PEPs can talk to a single endpoint.
//!
//! Run with:
//!   cargo run -p rust-embedder
//!
//! Then issue a request:
//!   curl -s http://127.0.0.1:8443/healthz
//!   curl -s http://127.0.0.1:8443/version
//!
//! The PDP routes (`/access/v1/evaluation`, `/access/v1/health`, ...)
//! are documented in `docs/architecture.md`.

use std::net::SocketAddr;
use std::path::PathBuf;

use agentguard_server::listener::{Listener, ServerConfig};
use anyhow::Context;
use axum::{routing::get, Json};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rust_embedder=info".into()),
        )
        .init();

    let store_root = PathBuf::from(".agentguard");
    let audit_log = Some(PathBuf::from(".audit/embedder-decisions.jsonl"));

    let cfg = ServerConfig {
        listener: Listener::Tcp("127.0.0.1:8443".parse::<SocketAddr>().unwrap()),
        store_root,
        audit_log,
        chain_secret: None,
        auth: agentguard_server::AuthConfig::Disabled,
        grpc_listener: None,
    };

    let (pdp, _state) = agentguard_server::build_router(cfg, true)
        .await
        .context("build agentguard router")?;

    let app = axum::Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/version", get(|| async { Json(json!({"name": "rust-embedder"})) }))
        .nest("/access/v1", pdp);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8443").await?;
    tracing::info!("rust-embedder listening on http://127.0.0.1:8443");
    axum::serve(listener, app).await?;
    Ok(())
}

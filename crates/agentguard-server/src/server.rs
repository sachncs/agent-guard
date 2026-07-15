//! Server entry point: `agentguard serve`.
//!
//! Callers that need to embed the server in their own binary should use
//! [`run`] directly. The binary in `bin/agentguard-server.rs` parses
//! CLI args and constructs a `ServerConfig` from them.
//!
//! The previous `make_run` and `config_from_env` helpers were dead code —
//! they were not called by any caller in the workspace. Removed in v0.2.0
//! as a deliberate API cleanup. External users who relied on them should
//! inline the equivalent at the call site:
//!
//! ```ignore
//! use agentguard_server::{run, ServerConfig};
//! use agentguard_server::listener::Listener;
//! let cfg = ServerConfig {
//!     listener: Listener::Tcp("127.0.0.1:8443".parse().unwrap()),
//!     store_root: ".agentguard".into(),
//!     audit_log: Some(".audit/decisions.jsonl".into()),
//!     chain_secret: None,
//! };
//! agentguard_server::run(cfg).await?;
//! ```

use crate::authzen::{build_state, router};
use crate::listener::Listener;
use crate::listener::ServerConfig;
use anyhow::{anyhow, Result};
use axum::serve::serve;
use tokio::net::TcpListener;
use tokio::signal;

/// Run the server. Returns when the listener stops (e.g. on SIGTERM/SIGINT).
/// In-flight requests are allowed to complete before the process exits.
///
/// # Errors
/// Returns an error if the listener can't be bound, the TLS material is
/// invalid, or the policy store can't be loaded.
pub async fn run(cfg: ServerConfig) -> Result<()> {
    let chain_secret = match &cfg.chain_secret {
        Some(path) => {
            let bytes =
                std::fs::read(path).map_err(|e| anyhow!("read chain secret {:?}: {}", path, e))?;
            if bytes.is_empty() {
                return Err(anyhow!("chain secret file {:?} is empty", path));
            }
            Some(bytes)
        }
        None => None,
    };
    let state = build_state(cfg.store_root.clone(), cfg.audit_log.clone(), chain_secret)
        .await
        .map_err(|e| anyhow!("build state: {}", e))?;
    let app = router(state);

    match cfg.listener {
        Listener::Tcp(addr) => {
            let listener = TcpListener::bind(addr).await?;
            tracing::info!("agentguard listening on tcp://{}", addr);
            serve(listener, app.into_make_service())
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
        Listener::Tls { addr, cert, key } => {
            use axum_server::tls_rustls::RustlsConfig;
            let cfg = RustlsConfig::from_pem_file(cert, key).await?;
            tracing::info!("agentguard listening on tls://{}", addr);
            // axum_server::Handle exposes shutdown; use it to coordinate
            // with our signal handler.
            let handle = axum_server::Handle::new();
            let signal_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                signal_handle.shutdown();
            });
            axum_server::bind_rustls(addr, cfg)
                .handle(handle)
                .serve(app.into_make_service())
                .await?;
        }
        Listener::Unix(path) => {
            // Unix socket support is a v2.1 enhancement. For now, the user
            // should use a TCP loopback listener (sidecars work fine that way).
            return Err(anyhow!(
                "Unix socket mode is not yet implemented; use tcp://127.0.0.1:<port> instead (path was {})",
                path.display()
            ));
        }
    }

    tracing::info!("agentguard stopped cleanly");
    Ok(())
}

/// Resolve when SIGINT or SIGTERM is received. Used as the trigger for
/// `axum::serve(...).with_graceful_shutdown(...)` so in-flight requests
/// finish before the process exits.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => tracing::info!("SIGINT received, draining"),
        _ = terminate => tracing::info!("SIGTERM received, draining"),
    }
}

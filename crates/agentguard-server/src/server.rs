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

use crate::auth_layer::AuthLayer;
use crate::authzen::{build_state, router};
use crate::listener::{Listener, ServerConfig};
use agentguard_policy::watcher::{watch as policy_watch, WatchEvent};
use anyhow::{anyhow, Result};
use axum::serve::serve;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;

/// Run the server. Returns when the listener stops (e.g. on SIGTERM/SIGINT).
/// In-flight requests are allowed to complete before the process exits.
///
/// # Errors
/// Returns an error if the listener can't be bound, the TLS material is
/// invalid, or the policy store can't be loaded.
pub async fn run(cfg: ServerConfig) -> Result<()> {
    let allow_loopback_bypass = std::env::var("AGENTGUARD_ALLOW_LOOPBACK_BYPASS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if matches!(cfg.auth, crate::listener::AuthConfig::Disabled) && cfg.listener.is_public() {
        if allow_loopback_bypass {
            tracing::warn!(
                "AGENTGUARD_ALLOW_LOOPBACK_BYPASS=1: serving unauthenticated decisions on a public listener; \
                 this should only happen behind a trusted reverse proxy"
            );
        } else {
            return Err(anyhow!(
                "auth is disabled but the listener is not loopback-bound; \
                 set AGENTGUARD_AUTH=apikey:<path> or AGENTGUARD_ALLOW_LOOPBACK_BYPASS=1"
            ));
        }
    }
    let auth = AuthLayer::from_config(&cfg.auth, allow_loopback_bypass)
        .map_err(|e| anyhow!("auth layer: {}", e))?;
    let chain_secret = match &cfg.chain_secret {
        Some(path) => {
            let bytes =
                std::fs::read(path).map_err(|e| anyhow!("read chain secret {:?}: {}", path, e))?;
            if bytes.is_empty() {
                return Err(anyhow!("chain secret file {:?} is empty", path));
            }
            Some(bytes)
        }
        None => {
            if cfg.audit_log.is_some() {
                tracing::warn!(
                    "AGENTGUARD_CHAIN_SECRET is not set; audit log will be plain JSONL (no tamper evidence)"
                );
            }
            None
        }
    };
    let state = Arc::new(
        build_state(
            cfg.store_root.clone(),
            cfg.audit_log.clone(),
            chain_secret,
            auth,
        )
        .await
        .map_err(|e| anyhow!("build state: {}", e))?,
    );
    let watcher_handle = spawn_policy_watcher(cfg.store_root.clone(), state.clone());
    let app = router((*state).clone());

    // Optional gRPC sidecar: when AGENTGUARD_GRPC_LISTEN is set,
    // spawn a tonic server on the given address alongside the HTTP
    // server. Same AppState, same authorizer — only the transport
    // differs.
    let grpc_handle = if let Some(addr) = cfg.grpc_listener {
        let svc = crate::grpc::service(state.clone());
        tracing::info!("agentguard gRPC listening on tcp://{}", addr);
        Some(tokio::spawn(async move {
            let res = tonic::transport::Server::builder()
                .add_service(svc)
                .serve(addr)
                .await;
            if let Err(e) = res {
                tracing::error!(error = %e, "gRPC server exited with error");
            }
        }))
    } else {
        None
    };

    match cfg.listener.clone() {
        Listener::Tcp(addr) => {
            let listener = TcpListener::bind(addr).await?;
            tracing::info!("agentguard listening on tcp://{}", addr);
            serve(listener, app.into_make_service())
                .with_graceful_shutdown(shutdown_signal_with_sighup(state.clone()))
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
            let state_for_signal = state.clone();
            tokio::spawn(async move {
                shutdown_signal_with_sighup(state_for_signal).await;
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

    watcher_handle.abort();
    if let Some(h) = grpc_handle {
        h.abort();
    }
    tracing::info!("agentguard stopped cleanly");
    Ok(())
}

/// Build a ready-to-serve `Router` from the config. Exposed for tests
/// and embedders that want to run the AuthZEN app inside their own
/// hyper server.
pub async fn build_router(
    cfg: ServerConfig,
) -> Result<(axum::Router, Arc<crate::authzen::AppState>)> {
    let allow_loopback_bypass = true;
    let auth = AuthLayer::from_config(&cfg.auth, allow_loopback_bypass)
        .map_err(|e| anyhow!("auth layer: {}", e))?;
    let chain_secret = match &cfg.chain_secret {
        Some(path) => {
            let bytes =
                std::fs::read(path).map_err(|e| anyhow!("read chain secret {:?}: {}", path, e))?;
            Some(bytes)
        }
        None => None,
    };
    let state = build_state(
        cfg.store_root.clone(),
        cfg.audit_log.clone(),
        chain_secret,
        auth,
    )
    .await
    .map_err(|e| anyhow!("build state: {}", e))?;
    let app = router(state.clone());
    Ok((app, Arc::new(state)))
}

/// Spawn the policy hot-reload watcher. Returns the task handle so the
/// caller can abort it on shutdown. The task polls the filesystem
/// every 500 ms, drains the watcher's debounced events, and on each
/// event invalidates the decision cache and increments
/// `policy_reload_total`.
///
/// `store_root` is the policy directory; we do not deeply watch the
/// schema or audit log.
pub fn spawn_policy_watcher(
    store_root: std::path::PathBuf,
    state: Arc<crate::authzen::AppState>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let mut watcher = match policy_watch(&store_root, Duration::from_millis(250)) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(
                    store_root = %store_root.display(),
                    error = %e,
                    "policy watcher init failed; hot reload disabled"
                );
                // Park forever so the JoinHandle stays valid.
                std::thread::park();
                return;
            }
        };
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let events: Vec<WatchEvent> = watcher.events();
            if events.is_empty() {
                continue;
            }
            // ponytail: simple invalidation. Re-loading the policy
            // set is the Authorizer's job; for now we invalidate
            // the cache and bump the counter. A full reload rebuilds
            // the cedar PolicySet, which is a bigger lift.
            state.authorizer().invalidate_cache();
            state.metrics().record_policy_reload();
            tracing::info!(events = events.len(), "policy reload triggered by watcher");
        }
    })
}

/// Block until SIGINT, SIGTERM, or (on Unix) SIGHUP is received.
/// SIGHUP triggers an immediate cache invalidation + reload-counter
/// bump so operators can force a refresh without touching the
/// filesystem.
pub async fn shutdown_signal_with_sighup(state: Arc<crate::authzen::AppState>) {
    #[cfg(unix)]
    let sighup = async {
        if let Ok(mut sig) = signal::unix::signal(signal::unix::SignalKind::hangup()) {
            sig.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(not(unix))]
    let sighup = std::future::pending::<()>();
    let ctrl_c = async {
        // ponytail: ctrl_c returns Err when the handler can't be
        // installed (sandbox). Park forever so shutdown stays
        // well-defined rather than exiting early.
        if signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
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
        _ = sighup => {
            state.authorizer().invalidate_cache();
            state.metrics().record_policy_reload();
            tracing::info!("SIGHUP received; cache invalidated, awaiting actual shutdown");
            // Don't return; wait for SIGINT/SIGTERM next.
            Box::pin(shutdown_signal_with_sighup(state.clone())).await;
        }
    }
}

/// Resolve when SIGINT or SIGTERM is received. Used as the trigger for
/// `axum::serve(...).with_graceful_shutdown(...)` so in-flight requests
/// finish before the process exits.
#[allow(dead_code)]
async fn shutdown_signal() {
    let ctrl_c = async {
        // ponytail: ctrl_c returns Err when the handler can't be
        // installed (sandbox). Park forever so shutdown stays
        // well-defined rather than exiting early.
        if signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
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

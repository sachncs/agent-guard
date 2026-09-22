//! Server entry point: `agentguard-server`.
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
use agentguard_core::decode_chain_secret;
use agentguard_policy::watcher::watch as policy_watch;
use anyhow::{anyhow, Result};
use axum::serve::serve;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;

/// Validate that both TLS files exist, are readable, and are
/// non-empty. Used at the top of [`run`] so a misconfigured cert /
/// key path fails before the policy store loads or the HTTP
/// listener binds.
pub(crate) fn validate_tls_paths(cert: &Path, key: &Path) -> Result<()> {
    for (label, path) in [("cert", cert), ("key", key)] {
        let meta = std::fs::metadata(path)
            .map_err(|e| anyhow!("tls {label} {:?} not readable: {e}", path.display()))?;
        if !meta.is_file() {
            return Err(anyhow!(
                "tls {label} {:?} is not a regular file",
                path.display()
            ));
        }
        if meta.len() == 0 {
            return Err(anyhow!("tls {label} {:?} is empty", path.display()));
        }
    }
    Ok(())
}

/// Run the server. Returns when the listener stops (e.g. on SIGTERM/SIGINT).
/// In-flight requests are allowed to complete before the process exits.
///
/// # Errors
/// Returns an error if the listener can't be bound, the TLS material is
/// invalid, or the policy store can't be loaded.
pub async fn run(cfg: ServerConfig) -> Result<()> {
    // Validate TLS paths early so a bad tls://addr?cert=PATH&key=PATH
    // is reported at startup, not after the policy store loads and
    // the HTTP listener binds.
    if let crate::listener::Listener::Tls { cert, key, .. } = &cfg.listener {
        validate_tls_paths(cert, key)?;
    }
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
    let key_watcher_target = auth.reloadable_key_store();
    let chain_secret = match &cfg.chain_secret {
        Some(path) => {
            let bytes =
                std::fs::read(path).map_err(|e| anyhow!("read chain secret {:?}: {}", path, e))?;
            let bytes = decode_chain_secret(&bytes)
                .ok_or_else(|| anyhow!("chain secret file {:?} is empty", path))?;
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
    let key_watcher_handle = key_watcher_target
        .map(|(path, store)| spawn_api_key_watcher(path, store))
        .transpose()?;
    let watcher_handle =
        spawn_policy_watcher(cfg.store_root.clone(), state.clone() as Arc<dyn ReloadSink>);
    let app = router((*state).clone());

    // Optional gRPC sidecar: when AGENTGUARD_GRPC_LISTEN is set,
    // spawn a tonic server on the given address alongside the HTTP
    // server. Same AppState, same authorizer — only the transport
    // differs.
    let grpc_handle = if let Some(addr) = cfg.grpc_listener {
        if !addr.ip().is_loopback() {
            return Err(anyhow!(
                "gRPC listener must be loopback-bound until TLS is supported"
            ));
        }
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
                // The orchestrator owns the hard termination deadline
                // (terminationGracePeriodSeconds in the Kubernetes base).
                // Do not timeout the signal future itself: doing so asks
                // Axum to shut down after 30 seconds even when no signal was
                // received.
                .with_graceful_shutdown(shutdown_signal_with_sighup(state.clone()))
                .await?;
        }
        Listener::Tls { addr, cert, key } => {
            use axum_server::tls_rustls::RustlsConfig;
            let cfg = RustlsConfig::from_pem_file(cert, key).await?;
            tracing::info!("agentguard listening on tls://{}", addr);
            // axum_server::Handle exposes shutdown; use it to coordinate
            // with our signal handler. The orchestrator owns the hard
            // termination deadline.
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
    }

    watcher_handle.abort();
    if let Some(handle) = key_watcher_handle {
        handle.abort();
    }
    if let Some(h) = grpc_handle {
        h.abort();
    }
    tracing::info!("agentguard stopped cleanly");
    Ok(())
}

/// Build a ready-to-serve `Router` from the config. Exposed for tests
/// and embedders that want to run the AuthZEN app inside their own
/// hyper server.
///
/// `allow_loopback_bypass`: when `true`, a config with auth disabled
/// may be served on a non-loopback listener (intended only for
/// tests and embedders behind a trusted reverse proxy). Production
/// callers should pass `false` so the security guard fires.
pub async fn build_router(
    cfg: ServerConfig,
    allow_loopback_bypass: bool,
) -> Result<(axum::Router, Arc<crate::authzen::AppState>)> {
    let auth = AuthLayer::from_config(&cfg.auth, allow_loopback_bypass)
        .map_err(|e| anyhow!("auth layer: {}", e))?;
    let chain_secret = match &cfg.chain_secret {
        Some(path) => {
            let bytes =
                std::fs::read(path).map_err(|e| anyhow!("read chain secret {:?}: {}", path, e))?;
            decode_chain_secret(&bytes)
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

/// Minimal sink the watcher needs from app state. Implemented by
/// `AppState` so tests can pass a fake.
pub trait ReloadSink: Send + Sync + 'static {
    /// Replace the policy snapshot and bump `policy_reload_total`.
    fn reload(&self);
}

impl ReloadSink for crate::authzen::AppState {
    fn reload(&self) {
        match self.authorizer().reload() {
            Ok(()) => {
                self.metrics().record_policy_reload();
                tracing::info!("policy snapshot reloaded");
            }
            Err(error) => {
                tracing::error!(%error, "policy reload failed; retaining last known-good snapshot");
            }
        }
    }
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
    sink: Arc<dyn ReloadSink>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut watcher = match policy_watch(&store_root, Duration::from_millis(250)) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(
                    store_root = %store_root.display(),
                    error = %e,
                    "policy watcher init failed; hot reload disabled"
                );
                return;
            }
        };
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        loop {
            interval.tick().await;
            let events = watcher.events();
            if events.is_empty() {
                continue;
            }
            sink.reload();
            tracing::info!(events = events.len(), "policy reload triggered by watcher");
        }
    })
}

/// Watch the parent directory of a mounted API-key file and reload the
/// complete key set after projected-secret updates or atomic CLI writes.
/// Invalid snapshots retain the current key set and are reported loudly;
/// the next filesystem event retries the load.
pub fn spawn_api_key_watcher(
    path: std::path::PathBuf,
    store: Arc<agentguard_auth::ApiKeyStore>,
) -> Result<tokio::task::JoinHandle<()>> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut watcher = policy_watch(parent, Duration::from_millis(250)).map_err(|error| {
        anyhow!(
            "watch API-key store directory {:?}: {error}",
            parent.display()
        )
    })?;
    Ok(tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        loop {
            interval.tick().await;
            if watcher.events().is_empty() {
                continue;
            }
            match store.reload_from_file(&path) {
                Ok(()) => tracing::info!(key_store = %path.display(), "API-key store reloaded"),
                Err(error) => tracing::error!(
                    key_store = %path.display(),
                    %error,
                    "API-key store reload failed; retaining last known-good key set"
                ),
            }
        }
    }))
}

/// Block until SIGINT or SIGTERM is received. SIGHUP is handled
/// inline: each received SIGHUP triggers an immediate policy snapshot
/// reload so operators can force a
/// refresh without touching the filesystem. The loop is iterative
/// (no recursion) so multiple SIGHUPs don't grow the stack.
pub async fn shutdown_signal_with_sighup(state: Arc<crate::authzen::AppState>) {
    use tokio::signal::unix as u;

    // Best-effort installation of signal handlers. If install fails
    // (e.g. inside a sandbox) we park that branch forever so the
    // shutdown wait stays well-defined.
    #[cfg(unix)]
    let (mut terminate, mut sighup) = {
        let t = u::signal(u::SignalKind::terminate()).ok();
        let h = u::signal(u::SignalKind::hangup()).ok();
        (t, h)
    };
    #[cfg(not(unix))]
    let (mut terminate, mut sighup): (Option<Never>, Option<Never>) = (None, None);

    loop {
        // Pick the first signal that fires.
        tokio::select! {
            // ctrl_c returns Result<(), io::Error>; a sandbox that
            // can't install the handler reports Err — we park forever
            // so shutdown stays well-defined.
            res = signal::ctrl_c() => {
                if res.is_err() {
                    std::future::pending::<()>().await;
                } else {
                    tracing::info!("SIGINT received, draining");
                    break;
                }
            }
            _ = async {
                match terminate.as_mut() {
                    Some(s) => { let _ = s.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                tracing::info!("SIGTERM received, draining");
                break;
            }
            _ = async {
                match sighup.as_mut() {
                    Some(s) => { let _ = s.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                match state.authorizer().reload() {
                    Ok(()) => state.metrics().record_policy_reload(),
                    Err(error) => tracing::error!(%error, "policy reload failed after SIGHUP; retaining last known-good snapshot"),
                }
                tracing::info!(
                    "SIGHUP received; cache invalidated, awaiting actual shutdown"
                );
                // Loop again — wait for SIGINT/SIGTERM.
            }
        }
    }
}

/// Helper: phantom type for non-Unix branches where the signal futures
/// can never resolve (signals don't exist on Windows).
#[cfg(not(unix))]
type Never = std::convert::Infallible;

#[cfg(test)]
mod tls_validation_tests {
    use super::validate_tls_paths;
    use std::io::Write;

    #[test]
    fn missing_cert_reports_helpful_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("does-not-exist.pem");
        let key = dir.path().join("also-missing.pem");
        let err = validate_tls_paths(&cert, &key).unwrap_err().to_string();
        assert!(err.contains("tls cert"), "missing label: {err}");
        assert!(
            err.contains("not readable"),
            "missing actionable reason: {err}"
        );
    }

    #[test]
    fn empty_cert_reports_helpful_error() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::File::create(&cert_path).unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let err = validate_tls_paths(&cert_path, &key_path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cert"), "missing cert label: {err}");
        assert!(err.contains("empty"), "missing size reason: {err}");
    }

    #[test]
    fn directory_instead_of_file_reports_helpful_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = validate_tls_paths(dir.path(), dir.path())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not a regular file"),
            "missing dir reason: {err}"
        );
    }
}

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
use crate::authzen::{build_state, build_state_with_options, router, AppStateOptions};
use crate::listener::{Listener, ServerConfig};
use agentguard_core::decision::{cache::DecisionCache, RotationConfig};
use agentguard_core::decode_chain_secret;
use agentguard_policy::watcher::{watch as policy_watch, PolicyWatcher};
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

fn validate_grpc_listener(addr: std::net::SocketAddr) -> Result<()> {
    if !addr.ip().is_loopback() {
        return Err(anyhow!(
            "gRPC listener must be loopback-bound until TLS is supported"
        ));
    }
    Ok(())
}

fn parse_audit_rotation(value: Option<&str>) -> Result<Option<RotationConfig>> {
    value
        .map(RotationConfig::parse)
        .transpose()
        .map_err(|error| anyhow!("AGENTGUARD_AUDIT_MAX_BYTES {error}"))
}

fn validate_listener_security(
    listener: &Listener,
    grpc_listener: Option<std::net::SocketAddr>,
    auth: &crate::listener::AuthConfig,
    allow_loopback_bypass: bool,
) -> Result<()> {
    if let Some(addr) = grpc_listener {
        validate_grpc_listener(addr)?;
    }
    if matches!(auth, crate::listener::AuthConfig::Disabled)
        && listener.is_public()
        && !allow_loopback_bypass
    {
        return Err(anyhow!(
            "auth is disabled but the listener is not loopback-bound; \
             set AGENTGUARD_AUTH=apikey:<path> or AGENTGUARD_ALLOW_LOOPBACK_BYPASS=1"
        ));
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
    let cache_config = DecisionCache::try_config_from_env()
        .map_err(|error| anyhow!("invalid decision cache configuration: {error}"))?;
    let audit_rotation = match std::env::var("AGENTGUARD_AUDIT_MAX_BYTES") {
        Ok(value) => parse_audit_rotation(Some(&value))?,
        Err(std::env::VarError::NotPresent) => parse_audit_rotation(None)?,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(anyhow!("AGENTGUARD_AUDIT_MAX_BYTES must be valid Unicode"));
        }
    };
    // Validate TLS paths early so a bad tls://addr?cert=PATH&key=PATH
    // is reported at startup, not after the policy store loads and
    // the HTTP listener binds.
    if let crate::listener::Listener::Tls { cert, key, .. } = &cfg.listener {
        validate_tls_paths(cert, key)?;
    }
    let allow_loopback_bypass = std::env::var("AGENTGUARD_ALLOW_LOOPBACK_BYPASS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    validate_listener_security(
        &cfg.listener,
        cfg.grpc_listener,
        &cfg.auth,
        allow_loopback_bypass,
    )?;
    if matches!(cfg.auth, crate::listener::AuthConfig::Disabled)
        && cfg.listener.is_public()
        && allow_loopback_bypass
    {
        tracing::warn!(
            "AGENTGUARD_ALLOW_LOOPBACK_BYPASS=1: serving unauthenticated decisions on a public listener; \
             this should only happen behind a trusted reverse proxy"
        );
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
        build_state_with_options(
            cfg.store_root.clone(),
            cfg.audit_log.clone(),
            chain_secret,
            auth,
            AppStateOptions {
                cache: Some(cache_config),
                audit_rotation,
            },
        )
        .await
        .map_err(|e| anyhow!("build state: {}", e))?,
    );
    let watcher_handle =
        try_spawn_policy_watcher(cfg.store_root.clone(), state.clone() as Arc<dyn ReloadSink>)
            .map_err(|error| anyhow!("initialize policy watcher: {error}"))?;
    let key_watcher_handle =
        key_watcher_target.map(|(path, store)| spawn_api_key_watcher(path, store));
    let app = router((*state).clone());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Optional gRPC sidecar: when AGENTGUARD_GRPC_LISTEN is set,
    // spawn a tonic server on the given address alongside the HTTP
    // server. Same AppState, same authorizer — only the transport
    // differs.
    let grpc_handle = if let Some(addr) = cfg.grpc_listener {
        let svc = crate::grpc::service(state.clone());
        tracing::info!("agentguard gRPC listening on tcp://{}", addr);
        Some(tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;
            let res = tonic::transport::Server::builder()
                .add_service(svc)
                .serve_with_shutdown(addr, async move {
                    if !*shutdown_rx.borrow() {
                        let _ = shutdown_rx.changed().await;
                    }
                })
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
                .with_graceful_shutdown(async move {
                    shutdown_signal_with_sighup(state.clone()).await;
                    let _ = shutdown_tx.send(true);
                })
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
            let grpc_shutdown_tx = shutdown_tx.clone();
            tokio::spawn(async move {
                shutdown_signal_with_sighup(state_for_signal).await;
                let _ = grpc_shutdown_tx.send(true);
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
        if let Err(error) = h.await {
            tracing::error!(%error, "gRPC shutdown task failed");
        }
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

/// Start the policy hot-reload watcher, returning an error if its filesystem
/// watch cannot be initialized. The task polls every 500 ms and reloads on
/// relevant policy/schema changes.
pub fn try_spawn_policy_watcher(
    store_root: std::path::PathBuf,
    sink: Arc<dyn ReloadSink>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let watcher = policy_watch(&store_root, Duration::from_millis(250))?;
    Ok(spawn_policy_watcher_task(watcher, sink))
}

/// Best-effort compatibility wrapper for callers that want watcher setup
/// failures logged asynchronously instead of returned.
pub fn spawn_policy_watcher(
    store_root: std::path::PathBuf,
    sink: Arc<dyn ReloadSink>,
) -> tokio::task::JoinHandle<()> {
    match policy_watch(&store_root, Duration::from_millis(250)) {
        Ok(watcher) => spawn_policy_watcher_task(watcher, sink),
        Err(error) => tokio::spawn(async move {
            tracing::error!(
                store_root = %store_root.display(),
                error = %error,
                "policy watcher init failed; hot reload disabled"
            );
        }),
    }
}

fn spawn_policy_watcher_task(
    mut watcher: PolicyWatcher,
    sink: Arc<dyn ReloadSink>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        loop {
            interval.tick().await;
            let events = watcher.events();
            for error in watcher.take_errors() {
                tracing::error!(%error, "policy filesystem watcher failed");
            }
            if events.is_empty() {
                continue;
            }
            sink.reload();
            tracing::info!(events = events.len(), "policy reload triggered by watcher");
        }
    })
}

/// Poll the API-key file contents and reload complete snapshots after
/// projected-secret updates or atomic CLI writes. Kubernetes updates Secret
/// volumes by swapping symlinks, which is not consistently reported by
/// directory watchers across filesystems. Invalid snapshots retain the
/// current key set; a later distinct file snapshot is retried.
pub fn spawn_api_key_watcher(
    path: std::path::PathBuf,
    store: Arc<agentguard_auth::ApiKeyStore>,
) -> tokio::task::JoinHandle<()> {
    // Capture the baseline before spawning so an update immediately after
    // this function returns cannot be mistaken for the initial snapshot.
    let mut last_attempted_snapshot = std::fs::read(&path).ok();
    if let Err(error) = store.reload_from_file(&path) {
        tracing::error!(
            key_store = %path.display(),
            %error,
            "initial API-key store refresh failed; retaining last known-good key set"
        );
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_read_error_log = None;
        loop {
            interval.tick().await;
            match std::fs::read(&path) {
                Ok(snapshot) => {
                    last_read_error_log = None;
                    if last_attempted_snapshot.as_ref() != Some(&snapshot) {
                        match store.reload_from_file(&path) {
                            Ok(()) => tracing::info!(
                                key_store = %path.display(),
                                "API-key store reloaded"
                            ),
                            Err(error) => tracing::error!(
                                key_store = %path.display(),
                                %error,
                                "API-key store reload failed; retaining last known-good key set"
                            ),
                        }
                        // Suppress repeated errors for an unchanged invalid
                        // projection; a new byte snapshot automatically retries.
                        last_attempted_snapshot = Some(snapshot);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if last_attempted_snapshot.take().is_some() {
                        match store.reload_from_file(&path) {
                            Ok(()) => tracing::info!(
                                key_store = %path.display(),
                                "API-key store removed; active keys cleared"
                            ),
                            Err(error) => tracing::error!(
                                key_store = %path.display(),
                                %error,
                                "API-key store removal reload failed; retaining last known-good key set"
                            ),
                        }
                    }
                }
                Err(error) => {
                    let should_log = last_read_error_log
                        .map(|last: std::time::Instant| last.elapsed() >= Duration::from_secs(30))
                        .unwrap_or(true);
                    if should_log {
                        tracing::error!(
                            key_store = %path.display(),
                            %error,
                            "API-key store read failed; retaining last known-good key set"
                        );
                        last_read_error_log = Some(std::time::Instant::now());
                    }
                }
            }
        }
    })
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
    use super::{
        parse_audit_rotation, run, validate_grpc_listener, validate_listener_security,
        validate_tls_paths,
    };
    use crate::auth_layer::AuthLayer;
    use crate::listener::{AuthConfig, Listener, ServerConfig};
    use std::io::Write;
    use std::sync::Arc;

    struct NoopReloadSink;

    impl super::ReloadSink for NoopReloadSink {
        fn reload(&self) {}
    }

    #[tokio::test]
    async fn run_rejects_invalid_tls_material_before_loading_the_policy_store() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = ServerConfig {
            listener: Listener::Tls {
                addr: "127.0.0.1:0".parse().unwrap(),
                cert: dir.path().join("missing-cert.pem"),
                key: dir.path().join("missing-key.pem"),
            },
            store_root: dir.path().join("missing-policy-store"),
            audit_log: None,
            chain_secret: None,
            auth: AuthConfig::Disabled,
            grpc_listener: None,
        };

        let error = run(cfg).await.unwrap_err().to_string();
        assert!(
            error.contains("tls cert"),
            "unexpected startup error: {error}"
        );
        assert!(!dir.path().join("missing-policy-store").exists());
    }

    #[tokio::test]
    async fn run_rejects_empty_audit_chain_secret_before_loading_the_policy_store() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("chain-secret");
        std::fs::write(&secret, b"").unwrap();
        let cfg = ServerConfig {
            listener: Listener::Tcp("127.0.0.1:0".parse().unwrap()),
            store_root: dir.path().join("missing-policy-store"),
            audit_log: Some(dir.path().join("audit.jsonl")),
            chain_secret: Some(secret),
            auth: AuthConfig::Disabled,
            grpc_listener: None,
        };

        let error = run(cfg).await.unwrap_err().to_string();
        assert!(
            error.contains("chain secret file"),
            "unexpected startup error: {error}"
        );
        assert!(!dir.path().join("missing-policy-store").exists());
    }

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

    #[test]
    fn plaintext_grpc_listener_is_restricted_to_loopback() {
        assert!(validate_grpc_listener("127.0.0.1:9443".parse().unwrap()).is_ok());
        assert!(validate_grpc_listener("[::1]:9443".parse().unwrap()).is_ok());
        let err = validate_grpc_listener("0.0.0.0:9443".parse().unwrap())
            .unwrap_err()
            .to_string();
        assert!(err.contains("loopback-bound"));
    }

    #[test]
    fn audit_rotation_requires_a_positive_integer_when_configured() {
        assert!(parse_audit_rotation(None).unwrap().is_none());
        assert_eq!(
            parse_audit_rotation(Some("1048576"))
                .unwrap()
                .unwrap()
                .max_bytes,
            1_048_576
        );
        assert!(parse_audit_rotation(Some("0")).is_err());
        assert!(parse_audit_rotation(Some("many")).is_err());
    }

    #[test]
    fn fallible_policy_watcher_rejects_missing_store_root() {
        let dir = tempfile::tempdir().unwrap();
        let error = super::try_spawn_policy_watcher(
            dir.path().join("missing-store"),
            Arc::new(NoopReloadSink),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn filesystem_watcher_reloads_nested_policy_files() {
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let store = agentguard_core::PolicyStore::open(dir.path()).unwrap();
        store
            .write_policy("initial", "permit(principal, action, resource);")
            .unwrap();
        let state =
            crate::authzen::build_state(dir.path().to_path_buf(), None, None, AuthLayer::Disabled)
                .await
                .unwrap();
        assert_eq!(state.authorizer().policy_count(), 1);

        let watcher =
            super::try_spawn_policy_watcher(dir.path().to_path_buf(), Arc::new(state.clone()))
                .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let nested_policies = store.policies_dir().join("team");
        std::fs::create_dir_all(&nested_policies).unwrap();
        std::fs::write(
            nested_policies.join("second.cedar"),
            "forbid(principal, action, resource);",
        )
        .unwrap();

        tokio::time::timeout(Duration::from_secs(4), async {
            while state.authorizer().policy_count() != 2 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("nested subdirectory policy edit should reload the complete policy snapshot");
        watcher.abort();
    }

    #[test]
    fn unauthenticated_public_listener_requires_explicit_bypass() {
        let listener = Listener::Tcp("0.0.0.0:8443".parse().unwrap());
        let error =
            validate_listener_security(&listener, None, &AuthConfig::Disabled, false).unwrap_err();
        assert!(error.to_string().contains("auth is disabled"));
    }

    #[test]
    fn explicit_bypass_only_relaxes_http_auth_guard() {
        let listener = Listener::Tcp("0.0.0.0:8443".parse().unwrap());
        assert!(validate_listener_security(&listener, None, &AuthConfig::Disabled, true).is_ok());
        assert!(validate_listener_security(
            &listener,
            Some("0.0.0.0:9443".parse().unwrap()),
            &AuthConfig::Disabled,
            true
        )
        .is_err());
    }

    #[test]
    fn api_key_auth_allows_public_listener_without_bypass() {
        let listener = Listener::Tcp("0.0.0.0:8443".parse().unwrap());
        let auth = AuthConfig::ApiKey {
            path: "keys.json".into(),
        };
        assert!(validate_listener_security(&listener, None, &auth, false).is_ok());
    }
}

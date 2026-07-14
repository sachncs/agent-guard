//! Server entry point: `agentguard serve`.

use crate::authzen::{build_state, router};
use crate::listener::Listener;
use crate::listener::ServerConfig;
use anyhow::{anyhow, Result};
use axum::serve::serve;
use std::path::PathBuf;
use tokio::net::TcpListener;

pub async fn run(cfg: ServerConfig) -> Result<()> {
    let state = build_state(cfg.store_root.clone())
        .await
        .map_err(|e| anyhow!("build state: {}", e))?;
    let app = router(state);

    match cfg.listener {
        Listener::Tcp(addr) => {
            let listener = TcpListener::bind(addr).await?;
            tracing::info!("agentguard listening on tcp://{}", addr);
            serve(listener, app.into_make_service()).await?;
        }
        Listener::Tls { addr, cert, key } => {
            use axum_server::tls_rustls::RustlsConfig;
            let cfg = RustlsConfig::from_pem_file(cert, key).await?;
            tracing::info!("agentguard listening on tls://{}", addr);
            axum_server::bind_rustls(addr, cfg)
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

    Ok(())
}

/// Build the run function for the CLI.
pub fn make_run(
) -> impl FnOnce(ServerConfig) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
{
    |cfg| Box::pin(run(cfg))
}

/// Helper for constructing a default config from env vars.
pub fn config_from_env() -> Result<ServerConfig> {
    ServerConfig::from_env().map_err(|e| anyhow!(e))
}

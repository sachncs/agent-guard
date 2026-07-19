//! `agentguard-server` binary entry point.

use agentguard_server::listener::ServerConfig;
use anyhow::Result;
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, ValueEnum)]
#[clap(rename_all = "lower")]
enum AuthModeArg {
    /// No authentication (loopback-only deployment).
    Disabled,
    /// Bearer-token auth via a JSON API-key store.
    Apikey,
}

#[derive(Parser, Debug)]
#[command(name = "agentguard-server", version, about = "AuthZEN HTTP + gRPC PDP")]
struct Cli {
    /// Listen address: tcp:// or tls://
    #[arg(
        long,
        env = "AGENTGUARD_LISTEN",
        default_value = "tcp://127.0.0.1:8443"
    )]
    listen: String,

    /// Path to the policy store
    #[arg(long, env = "AGENTGUARD_STORE", default_value = ".agentguard")]
    store: String,

    /// Path to the decision log
    #[arg(
        long,
        env = "AGENTGUARD_AUDIT",
        default_value = ".audit/decisions.jsonl"
    )]
    audit: String,

    /// Authentication mode for `/access/v1/*` endpoints.
    ///
    /// For `apikey`, also pass `--auth-key-file <path>` to point at
    /// the JSON API-key store.
    #[arg(long, env = "AGENTGUARD_AUTH", value_enum, default_value_t = AuthModeArg::Disabled)]
    auth: AuthModeArg,

    /// Path to the API-key store (when `--auth apikey`).
    #[arg(
        long,
        env = "AGENTGUARD_AUTH_KEY_FILE",
        requires = "auth_apikey"
    )]
    auth_key_file: Option<PathBuf>,

    /// Optional gRPC listen address (e.g. `0.0.0.0:9443`). When set,
    /// the server also serves the AuthZEN-compatible `AccessEvaluation`
    /// gRPC service on this port. Empty disables gRPC.
    #[arg(long, env = "AGENTGUARD_GRPC_LISTEN", default_value = "")]
    grpc_listen: String,
}

impl AuthModeArg {
    fn into_config(
        self,
        key_file: Option<PathBuf>,
    ) -> anyhow::Result<agentguard_server::AuthConfig> {
        match self {
            AuthModeArg::Disabled => Ok(agentguard_server::AuthConfig::Disabled),
            AuthModeArg::Apikey => {
                let path = key_file.ok_or_else(|| {
                    anyhow::anyhow!("--auth apikey requires --auth-key-file <path>")
                })?;
                Ok(agentguard_server::AuthConfig::ApiKey { path })
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,agentguard=debug")),
        )
        .init();

    let cli = Cli::parse();
    let listener = agentguard_server::listener::Listener::parse(&cli.listen)
        .map_err(|e| anyhow::anyhow!("invalid listen '{}': {}", cli.listen, e))?;

    let auth: agentguard_server::AuthConfig = cli.auth.into_config(cli.auth_key_file)?;

    let grpc_listener = if cli.grpc_listen.is_empty() {
        None
    } else {
        Some(cli.grpc_listen.parse().map_err(|e| {
            anyhow::anyhow!("invalid --grpc-listen '{}': {}", cli.grpc_listen, e)
        })?)
    };

    let cfg = ServerConfig {
        listener,
        store_root: cli.store.into(),
        audit_log: Some(cli.audit.into()),
        chain_secret: std::env::var("AGENTGUARD_CHAIN_SECRET")
            .ok()
            .map(Into::into),
        auth,
        grpc_listener,
    };

    agentguard_server::run(cfg).await
}

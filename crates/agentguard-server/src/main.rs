//! `agentguard-server` binary entry point.

use agentguard_server::listener::ServerConfig;
use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "agentguard-server", version, about = "AuthZEN HTTP + gRPC PDP")]
struct Cli {
    /// Listen address: tcp://, tls://, or unix://
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

    /// Authentication mode: `disabled` or `apikey:<path>`.
    #[arg(long, env = "AGENTGUARD_AUTH", default_value = "disabled")]
    auth: String,
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

    let auth = if cli.auth == "disabled" || cli.auth.is_empty() {
        agentguard_server::AuthConfig::Disabled
    } else if let Some(rest) = cli.auth.strip_prefix("apikey:") {
        agentguard_server::AuthConfig::ApiKey { path: rest.into() }
    } else {
        return Err(anyhow::anyhow!(
            "invalid --auth {:?}: expected 'disabled' or 'apikey:<path>'",
            cli.auth
        ));
    };

    let cfg = ServerConfig {
        listener,
        store_root: cli.store.into(),
        audit_log: Some(cli.audit.into()),
        chain_secret: std::env::var("AGENTGUARD_CHAIN_SECRET")
            .ok()
            .map(Into::into),
        auth,
    };

    agentguard_server::run(cfg).await
}

//! `agentguard-server` binary entry point.

use agentguard_server::listener::ServerConfig;
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "agentguard-server",
    version,
    about = "AuthZEN HTTP PDP with an optional repository-defined gRPC mirror"
)]
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
    /// Use `apikey` with `--auth-key-file <path>`, or use the complete
    /// `apikey:<path>` form through `AGENTGUARD_AUTH`.
    #[arg(long, env = "AGENTGUARD_AUTH", default_value = "disabled")]
    auth: String,

    /// Path to the API-key store when `--auth apikey` is used.
    #[arg(long, env = "AGENTGUARD_AUTH_KEY_FILE")]
    auth_key_file: Option<PathBuf>,

    /// Optional gRPC listen address (e.g. `0.0.0.0:9443`). When set,
    /// the server also serves the repository-defined `AccessEvaluation`
    /// gRPC mirror on this port. It is plaintext and not standardized AuthZEN
    /// gRPC. Empty disables gRPC.
    #[arg(long, env = "AGENTGUARD_GRPC_LISTEN", default_value = "")]
    grpc_listen: String,
}

fn auth_config(
    mode: &str,
    key_file: Option<PathBuf>,
) -> anyhow::Result<agentguard_server::AuthConfig> {
    match mode {
        "disabled" => Ok(agentguard_server::AuthConfig::Disabled),
        "apikey" => {
            let path = key_file
                .ok_or_else(|| anyhow::anyhow!("--auth apikey requires --auth-key-file <path>"))?;
            Ok(agentguard_server::AuthConfig::ApiKey { path })
        }
        value if value.starts_with("apikey:") => {
            if key_file.is_some() {
                anyhow::bail!("do not combine AGENTGUARD_AUTH=apikey:<path> with --auth-key-file")
            }
            let path = value.trim_start_matches("apikey:");
            if path.is_empty() {
                anyhow::bail!("AGENTGUARD_AUTH=apikey:<path> requires a non-empty path")
            }
            Ok(agentguard_server::AuthConfig::ApiKey {
                path: PathBuf::from(path),
            })
        }
        value => anyhow::bail!(
            "--auth must be 'disabled', 'apikey', or 'apikey:<path>'; got {:?}",
            value
        ),
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

    let auth: agentguard_server::AuthConfig = auth_config(&cli.auth, cli.auth_key_file)?;

    let grpc_listener =
        if cli.grpc_listen.is_empty() {
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

#[cfg(test)]
mod tests {
    use super::auth_config;
    use agentguard_server::AuthConfig;
    use std::path::{Path, PathBuf};

    #[test]
    fn accepts_cli_mode_and_companion_key_file() {
        assert!(matches!(
            auth_config("apikey", Some(PathBuf::from("keys.json"))).unwrap(),
            AuthConfig::ApiKey { path } if path.as_path() == Path::new("keys.json")
        ));
    }

    #[test]
    fn accepts_documented_environment_form() {
        assert!(matches!(
            auth_config("apikey:/etc/agentguard/keys.json", None).unwrap(),
            AuthConfig::ApiKey { path } if path.as_path() == Path::new("/etc/agentguard/keys.json")
        ));
    }

    #[test]
    fn rejects_missing_or_conflicting_key_paths() {
        assert!(auth_config("apikey", None).is_err());
        assert!(auth_config("apikey:/keys.json", Some(PathBuf::from("other.json"))).is_err());
        assert!(auth_config("apikey:", None).is_err());
    }
}

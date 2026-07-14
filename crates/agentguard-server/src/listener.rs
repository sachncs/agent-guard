//! Server configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

/// How the server listens for connections.
#[derive(Debug, Clone)]
pub enum Listener {
    /// Plain TCP (use only for testing; production should use TLS).
    Tcp(SocketAddr),
    /// TLS-enabled TCP.
    Tls {
        addr: SocketAddr,
        cert: PathBuf,
        key: PathBuf,
    },
    /// Unix domain socket (K8s sidecar mode).
    Unix(PathBuf),
}

impl Listener {
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(rest) = s.strip_prefix("tcp://") {
            rest.parse::<SocketAddr>()
                .map(Listener::Tcp)
                .map_err(|e| format!("bad tcp addr: {}", e))
        } else if let Some(rest) = s.strip_prefix("tls://") {
            // tls://addr?cert=PATH&key=PATH
            let (addr, _) = rest.split_once('?').unwrap_or((rest, ""));
            let mut parts = std::collections::HashMap::new();
            if let Some(qs) = rest.split_once('?').map(|(_, q)| q) {
                for kv in qs.split('&') {
                    if let Some((k, v)) = kv.split_once('=') {
                        parts.insert(k.to_string(), v.to_string());
                    }
                }
            }
            let cert = parts
                .remove("cert")
                .ok_or_else(|| "tls:// requires ?cert=PATH".to_string())?;
            let key = parts
                .remove("key")
                .ok_or_else(|| "tls:// requires ?key=PATH".to_string())?;
            Ok(Listener::Tls {
                addr: addr
                    .parse::<SocketAddr>()
                    .map_err(|e| format!("bad tls addr: {}", e))?,
                cert: PathBuf::from(cert),
                key: PathBuf::from(key),
            })
        } else if let Some(rest) = s.strip_prefix("unix://") {
            Ok(Listener::Unix(PathBuf::from(rest)))
        } else {
            Err(format!("unknown listener scheme: {}", s))
        }
    }
}

/// Top-level server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listener: Listener,
    pub store_root: PathBuf,
    pub audit_log: PathBuf,
    /// Optional secret file for hash-chained audit log.
    pub chain_secret: Option<PathBuf>,
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, String> {
        let listener = std::env::var("AGENTGUARD_LISTEN")
            .unwrap_or_else(|_| "tcp://127.0.0.1:8443".to_string());
        let listener = Listener::parse(&listener)?;
        let store_root = PathBuf::from(
            std::env::var("AGENTGUARD_STORE").unwrap_or_else(|_| ".agentguard".to_string()),
        );
        let audit_log = PathBuf::from(
            std::env::var("AGENTGUARD_AUDIT")
                .unwrap_or_else(|_| ".audit/decisions.jsonl".to_string()),
        );
        let chain_secret = std::env::var("AGENTGUARD_CHAIN_SECRET")
            .ok()
            .map(PathBuf::from);
        Ok(Self {
            listener,
            store_root,
            audit_log,
            chain_secret,
        })
    }
}

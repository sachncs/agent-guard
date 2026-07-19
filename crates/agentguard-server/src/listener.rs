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
    /// True if the listener binds to a non-loopback address. Used to
    /// log a warning when auth is disabled on a public-facing socket.
    pub fn is_public(&self) -> bool {
        match self {
            Listener::Tcp(addr) => !addr.ip().is_loopback(),
            Listener::Tls { addr, .. } => !addr.ip().is_loopback(),
            Listener::Unix(_) => false,
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(rest) = s.strip_prefix("tcp://") {
            rest.parse::<SocketAddr>()
                .map(Listener::Tcp)
                .map_err(|e| format!("bad tcp addr: {}", e))
        } else if let Some(rest) = s.strip_prefix("tls://") {
            // tls://addr?cert=PATH&key=PATH
            let (addr, qs) = match rest.split_once('?') {
                Some((a, q)) => (a, q),
                None => (rest, ""),
            };
            let mut parts = std::collections::HashMap::new();
            for kv in qs.split('&').filter(|s| !s.is_empty()) {
                let (k, v) = kv
                    .split_once('=')
                    .ok_or_else(|| format!("malformed tls query: {}", kv))?;
                if parts.insert(k.to_string(), v.to_string()).is_some() {
                    return Err(format!("duplicate tls query key: {}", k));
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
        } else if s.starts_with("unix://") {
            // ponytail: fail fast at parse time so operators see
            // "unix:// not implemented" immediately, not after
            // binding the HTTP listener.
            Err("unix:// listener is not implemented yet; use tcp:// or tls://".to_string())
        } else {
            Err(format!("unknown listener scheme: {}", s))
        }
    }
}

/// Top-level server configuration.
#[derive(Debug, Clone, Default)]
pub enum AuthConfig {
    /// No authentication (development / loopback only).
    #[default]
    Disabled,
    /// Bearer-token authentication against a JSON API-key store.
    ApiKey {
        /// Path to the JSON file holding the keys.
        path: PathBuf,
    },
}

impl AuthConfig {
    /// Read `AGENTGUARD_AUTH` from the environment. Format:
    /// `disabled` (default) or `apikey:<path>`.
    pub fn from_env() -> Result<Self, String> {
        match std::env::var("AGENTGUARD_AUTH").ok().as_deref() {
            None | Some("") | Some("disabled") => Ok(AuthConfig::Disabled),
            Some(s) => {
                if let Some(rest) = s.strip_prefix("apikey:") {
                    Ok(AuthConfig::ApiKey {
                        path: PathBuf::from(rest),
                    })
                } else {
                    Err(format!(
                        "AGENTGUARD_AUTH must be 'disabled' or 'apikey:<path>', got {:?}",
                        s
                    ))
                }
            }
        }
    }
}

/// Top-level server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listener: Listener,
    pub store_root: PathBuf,
    /// Path to the audit log. The server writes every authorization
    /// decision to this file. **Required for production.**
    pub audit_log: Option<PathBuf>,
    /// Optional secret file for hash-chained audit log.
    pub chain_secret: Option<PathBuf>,
    /// Authentication mode for `/access/v1/*` endpoints.
    pub auth: AuthConfig,
    /// Optional gRPC listener. When `Some`, the server also serves
    /// the `AccessEvaluation` gRPC service on this address.
    pub grpc_listener: Option<std::net::SocketAddr>,
}

impl ServerConfig {
    pub fn from_env() -> Result<Self, String> {
        let listener = std::env::var("AGENTGUARD_LISTEN")
            .unwrap_or_else(|_| "tcp://127.0.0.1:8443".to_string());
        let listener = Listener::parse(&listener)?;
        let store_root = PathBuf::from(
            std::env::var("AGENTGUARD_STORE").unwrap_or_else(|_| ".agentguard".to_string()),
        );
        let audit_log = std::env::var("AGENTGUARD_AUDIT")
            .ok()
            .map(PathBuf::from)
            .or_else(|| Some(PathBuf::from(".audit/decisions.jsonl")));
        let chain_secret = std::env::var("AGENTGUARD_CHAIN_SECRET")
            .ok()
            .map(PathBuf::from);
        let auth = AuthConfig::from_env()?;
        let grpc_listener = std::env::var("AGENTGUARD_GRPC_LISTEN").ok().and_then(|s| {
            if s.is_empty() {
                None
            } else {
                s.parse().ok()
            }
        });
        Ok(Self {
            listener,
            store_root,
            audit_log,
            chain_secret,
            auth,
            grpc_listener,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_listener_rejected_at_parse_time() {
        // unix:// is unimplemented; parse must fail before the server
        // even tries to bind anything. Otherwise the user sees
        // "started" logs and only learns when the bind fails.
        let err = Listener::parse("unix:///tmp/agentguard.sock").unwrap_err();
        assert!(err.contains("unix://"), "got: {err}");
    }

    #[test]
    fn tls_query_string_rejects_duplicate_keys() {
        // Duplicate `cert=` would silently overwrite the first
        // value, hiding a typo from the operator.
        let err = Listener::parse("tls://0.0.0.0:8443?cert=a&cert=b&key=k").unwrap_err();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn is_public_returns_true_for_non_loopback_tcp() {
        let l = Listener::Tcp("0.0.0.0:8443".parse().unwrap());
        assert!(l.is_public());
        let l = Listener::Tcp("127.0.0.1:8443".parse().unwrap());
        assert!(!l.is_public());
    }
}

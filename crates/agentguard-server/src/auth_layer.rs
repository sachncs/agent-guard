//! Authentication middleware for the AuthZEN HTTP server.
//!
//! Modes:
//! - [`AuthConfig::Disabled`] — no auth. Suitable for development or
//!   loopback-only deployments. The server refuses to start with
//!   `Disabled` auth on a non-loopback bind unless
//!   `AGENTGUARD_ALLOW_LOOPBACK_BYPASS=1` is set.
//! - [`AuthConfig::ApiKey`] — `Authorization: Bearer <raw>` against
//!   the configured `ApiKeyStore`. Argon2id is the verification path;
//!   the cost (~150 ms) is acceptable on the auth path.
//!
//! Health probes (`/healthz`, `/readyz`) are always unauthenticated
//! so Kubernetes can poll them without a credential.

use crate::authzen::AppState;
use crate::listener::AuthConfig;
use agentguard_auth::{ApiKeyIdentity, ApiKeyStore};
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Argon2 verification uses substantial CPU and memory. Keep its blocking
/// work off async workers and cap concurrent verifications independently of
/// request concurrency (two 64 MiB hashes fit the default PDP memory budget).
const MAX_CONCURRENT_API_KEY_VERIFICATIONS: usize = 2;

/// Authenticated identity and tenant asserted by a verified, bound API key.
#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity(pub ApiKeyIdentity);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationFailure {
    Unauthenticated,
    Forbidden,
    Unavailable,
}

/// What the auth layer needs to validate requests. Built once at
/// startup and shared across Axum workers.
#[derive(Clone)]
pub enum AuthLayer {
    Disabled,
    ApiKey(Arc<ApiKeyStore>),
    ReloadableApiKey {
        store: Arc<ApiKeyStore>,
        path: std::path::PathBuf,
    },
}

impl AuthLayer {
    /// Build from the configured mode.
    pub fn from_config(cfg: &AuthConfig, allow_loopback_bypass: bool) -> Result<Self, String> {
        let layer = match cfg {
            AuthConfig::Disabled => AuthLayer::Disabled,
            AuthConfig::ApiKey { path } => {
                let store = ApiKeyStore::load_from_file(path)
                    .map_err(|e| format!("load api-key store {:?}: {}", path, e))?;
                AuthLayer::ReloadableApiKey {
                    store: Arc::new(store),
                    path: path.clone(),
                }
            }
        };
        if allow_loopback_bypass && matches!(layer, AuthLayer::Disabled) {
            tracing::warn!(
                "AGENTGUARD_ALLOW_LOOPBACK_BYPASS=1: auth disabled; \
                 operator assumes the listener is loopback-bound"
            );
        }
        Ok(layer)
    }

    /// Return the key-store source used by the standalone lifecycle so it
    /// can watch and atomically reload operator rotations/revocations.
    pub fn reloadable_key_store(&self) -> Option<(std::path::PathBuf, Arc<ApiKeyStore>)> {
        match self {
            Self::ReloadableApiKey { store, path } => Some((path.clone(), store.clone())),
            Self::Disabled | Self::ApiKey(_) => None,
        }
    }

    /// Authenticate non-HTTP transports using the same scope and identity
    /// requirements as the AuthZEN HTTP endpoints.
    pub fn authenticate_bearer(
        &self,
        authorization: Option<&str>,
        required_scope: &str,
        require_identity: bool,
    ) -> Result<Option<AuthenticatedIdentity>, AuthenticationFailure> {
        match self {
            Self::Disabled => Ok(None),
            Self::ApiKey(store) | Self::ReloadableApiKey { store, .. } => {
                let token = authorization
                    .and_then(|value| {
                        value
                            .strip_prefix("Bearer ")
                            .or_else(|| value.strip_prefix("bearer "))
                    })
                    .ok_or(AuthenticationFailure::Unauthenticated)?;
                let key = store
                    .verify(token)
                    .map_err(|_| AuthenticationFailure::Unauthenticated)?;
                if !key.has_scope(required_scope) {
                    return Err(AuthenticationFailure::Forbidden);
                }
                let identity = key.identity.ok_or(if require_identity {
                    AuthenticationFailure::Forbidden
                } else {
                    AuthenticationFailure::Unauthenticated
                });
                match identity {
                    Ok(identity) => Ok(Some(AuthenticatedIdentity(identity))),
                    Err(AuthenticationFailure::Unauthenticated) if !require_identity => Ok(None),
                    Err(err) => Err(err),
                }
            }
        }
    }

    /// Authenticate without running the memory-hard hash on a Tokio worker.
    /// Saturation fails fast so hostile traffic cannot build an unbounded
    /// queue of expensive password-hash jobs.
    pub async fn authenticate_bearer_async(
        &self,
        authorization: Option<&str>,
        required_scope: &str,
        require_identity: bool,
    ) -> Result<Option<AuthenticatedIdentity>, AuthenticationFailure> {
        self.authenticate_bearer_async_with_slots(
            authorization,
            required_scope,
            require_identity,
            api_key_verification_slots(),
        )
        .await
    }

    async fn authenticate_bearer_async_with_slots(
        &self,
        authorization: Option<&str>,
        required_scope: &str,
        require_identity: bool,
        slots: Arc<Semaphore>,
    ) -> Result<Option<AuthenticatedIdentity>, AuthenticationFailure> {
        if matches!(self, Self::Disabled) {
            return self.authenticate_bearer(authorization, required_scope, require_identity);
        }
        // Reject absent or structurally malformed credentials before taking
        // a scarce Argon2 slot. This keeps anonymous probes cheap under load.
        let token = authorization
            .and_then(|value| {
                value
                    .strip_prefix("Bearer ")
                    .or_else(|| value.strip_prefix("bearer "))
            })
            .ok_or(AuthenticationFailure::Unauthenticated)?;
        let mut parts = token.split(':');
        if parts.next().is_none_or(str::is_empty)
            || parts.next().is_none_or(str::is_empty)
            || parts.next().is_none_or(str::is_empty)
            || parts.next().is_some()
        {
            return Err(AuthenticationFailure::Unauthenticated);
        }
        let permit = slots
            .try_acquire_owned()
            .map_err(|_| AuthenticationFailure::Unavailable)?;
        let layer = self.clone();
        let authorization = authorization.map(str::to_owned);
        let required_scope = required_scope.to_owned();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            layer.authenticate_bearer(authorization.as_deref(), &required_scope, require_identity)
        })
        .await
        .map_err(|_| AuthenticationFailure::Unavailable)?
    }
}

fn api_key_verification_slots() -> Arc<Semaphore> {
    static SLOTS: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
    SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_API_KEY_VERIFICATIONS)))
        .clone()
}

/// Middleware function. Wire via `axum::middleware::from_fn_with_state`
/// because the router's state is needed for the auth layer reference.
pub async fn auth_layer_fn(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path == "/healthz" || path == "/readyz" {
        return next.run(req).await;
    }
    let method = req.method();
    let (required_scope, require_identity) = match (method.as_str(), path) {
        ("POST", "/access/v1/evaluation" | "/access/v1/evaluations") => ("authorize", true),
        ("GET", "/metrics") => ("metrics:read", false),
        _ => ("", false),
    };
    match &state.auth {
        AuthLayer::Disabled => next.run(req).await,
        AuthLayer::ApiKey(_) | AuthLayer::ReloadableApiKey { .. } => {
            let identity = match state
                .auth
                .authenticate_bearer_async(
                    req.headers()
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok()),
                    required_scope,
                    require_identity,
                )
                .await
            {
                Ok(identity) => identity,
                Err(AuthenticationFailure::Unauthenticated) => return unauthorized(),
                Err(AuthenticationFailure::Forbidden) => return forbidden(),
                Err(AuthenticationFailure::Unavailable) => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "authentication capacity exhausted\n",
                    )
                        .into_response()
                }
            };
            let mut req = req;
            if let Some(identity) = identity {
                req.extensions_mut().insert(identity);
            }
            next.run(req).await
        }
    }
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response()
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "forbidden\n").into_response()
}

#[cfg(test)]
mod async_auth_tests {
    use super::{ApiKeyStore, AuthLayer, AuthenticationFailure};
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn saturated_verification_capacity_fails_fast() {
        let auth = AuthLayer::ApiKey(Arc::new(ApiKeyStore::new()));
        let result = auth
            .authenticate_bearer_async_with_slots(
                Some("Bearer ag_test:key-id:secret"),
                "authorize",
                true,
                Arc::new(Semaphore::new(0)),
            )
            .await;
        assert!(matches!(result, Err(AuthenticationFailure::Unavailable)));
    }

    #[tokio::test]
    async fn disabled_auth_stays_nonblocking_and_does_not_need_a_slot() {
        let result = AuthLayer::Disabled
            .authenticate_bearer_async_with_slots(
                None,
                "authorize",
                true,
                Arc::new(Semaphore::new(0)),
            )
            .await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn missing_credentials_do_not_consume_verification_capacity() {
        let auth = AuthLayer::ApiKey(Arc::new(ApiKeyStore::new()));
        let result = auth
            .authenticate_bearer_async_with_slots(
                None,
                "authorize",
                true,
                Arc::new(Semaphore::new(0)),
            )
            .await;
        assert!(matches!(
            result,
            Err(AuthenticationFailure::Unauthenticated)
        ));
    }

    #[tokio::test]
    async fn argon_verification_does_not_block_async_workers() {
        use agentguard_auth::ApiKeyIdentity;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let store = ApiKeyStore::new();
        let identity = ApiKeyIdentity::new("User", "alice", None).unwrap();
        let (_, raw) = store
            .create_bound("ag_test", vec!["authorize".into()], None, identity)
            .unwrap();
        let auth = AuthLayer::ApiKey(Arc::new(store));
        let ticks = Arc::new(AtomicUsize::new(0));
        let tick_count = ticks.clone();
        let ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(10));
            loop {
                interval.tick().await;
                tick_count.fetch_add(1, Ordering::Relaxed);
            }
        });

        let result = auth
            .authenticate_bearer_async_with_slots(
                Some(&format!("Bearer {raw}")),
                "authorize",
                true,
                Arc::new(Semaphore::new(1)),
            )
            .await;
        ticker.abort();

        assert!(matches!(result, Ok(Some(_))));
        assert!(
            ticks.load(Ordering::Relaxed) >= 2,
            "the async runtime should keep making progress during Argon2 verification"
        );
    }
}

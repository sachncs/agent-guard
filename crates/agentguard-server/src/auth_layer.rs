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

/// Authenticated identity and tenant asserted by a verified, bound API key.
#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity(pub ApiKeyIdentity);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationFailure {
    Unauthenticated,
    Forbidden,
}

/// What the auth layer needs to validate requests. Built once at
/// startup and shared across Axum workers.
#[derive(Clone)]
pub enum AuthLayer {
    Disabled,
    ApiKey(Arc<ApiKeyStore>),
}

impl AuthLayer {
    /// Build from the configured mode.
    pub fn from_config(cfg: &AuthConfig, allow_loopback_bypass: bool) -> Result<Self, String> {
        let layer = match cfg {
            AuthConfig::Disabled => AuthLayer::Disabled,
            AuthConfig::ApiKey { path } => {
                let store = ApiKeyStore::load_from_file(path)
                    .map_err(|e| format!("load api-key store {:?}: {}", path, e))?;
                AuthLayer::ApiKey(Arc::new(store))
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
            Self::ApiKey(store) => {
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
        AuthLayer::ApiKey(_) => {
            let identity = match state.auth.authenticate_bearer(
                req.headers()
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                required_scope,
                require_identity,
            ) {
                Ok(identity) => identity,
                Err(AuthenticationFailure::Unauthenticated) => return unauthorized(),
                Err(AuthenticationFailure::Forbidden) => return forbidden(),
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

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
use agentguard_auth::ApiKeyStore;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

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
}

/// Middleware function. Wire via `axum::middleware::from_fn_with_state`
/// because the router's state is needed for the auth layer reference.
pub async fn auth_layer_fn(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path == "/healthz" || path == "/readyz" {
        return next.run(req).await;
    }
    match &state.auth {
        AuthLayer::Disabled => next.run(req).await,
        AuthLayer::ApiKey(store) => {
            let token = match req
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| {
                    s.strip_prefix("Bearer ")
                        .or_else(|| s.strip_prefix("bearer "))
                }) {
                Some(t) => t.to_string(),
                None => return unauthorized(),
            };
            // ponytail: surface 401 with a generic body so the error
            // message doesn't distinguish "no such key" from "wrong
            // secret" — defeats enumeration.
            if store.verify(&token).is_err() {
                return unauthorized();
            }
            next.run(req).await
        }
    }
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response()
}

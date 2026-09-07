//! Error types for agentguard-core.
//!
//! Two parallel hierarchies are intentionally maintained: this crate
//! (`agentguard_core::Error`) covers authorization-engine failures
//! (Cedar parse, schema validation, decision evaluation, delegation token
//! issues), while `agentguard_auth::AuthError` covers authentication
//! failures (JWT, OIDC, API keys, DPoP, SPIFFE). Merging them would create
//! a circular dependency between `agentguard-core` and `agentguard-auth`,
//! since `agentguard-auth` depends on `agentguard-core` for the
//! `Principal` and `AgentAction` types.
//!
//! Callers handling both (e.g. the AuthZEN server) match on each
//! separately. `anyhow::Result` or `Box<dyn std::error::Error + Send +
//! Sync>` is the right type for code paths that span both.
//!
//! When converting from one to the other, use
//! `.map_err(|e| Error::Other(e.to_string()))`. A future v2.1 may add a
//! unified error type behind a feature flag without breaking this design.

use thiserror::Error;

/// Result alias for agentguard-core fallible operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by agentguard-core.
///
/// `#[non_exhaustive]` lets the v2.x line add new variants without breaking
/// downstream exhaustive matches.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("io error: {0}")]
    Io(String),

    #[error("json error: {0}")]
    Json(String),

    #[error("policy parse error in {file}: {message}")]
    PolicyParse {
        /// Human-readable parse error.
        message: String,
        /// File or virtual file where the policy lives (e.g. `policy0.cedar`).
        file: String,
    },

    #[error("schema error: {0}")]
    Schema(String),

    #[error("invalid principal: {0}")]
    InvalidPrincipal(String),

    #[error("invalid resource: {0}")]
    InvalidResource(String),

    #[error("invalid context: {0}")]
    InvalidContext(String),

    #[error("invalid delegation token: {0}")]
    InvalidToken(String),

    #[error("token expired at {0}")]
    TokenExpired(String),

    #[error("token signature invalid: {reason}")]
    TokenSignature {
        /// Why the signature failed verification (bad signature, unknown kid, etc.).
        reason: String,
    },

    #[error("token not yet valid (nbf={0})")]
    TokenNotYetValid(String),

    #[error("policy validation failed: {0}")]
    Validation(String),

    #[error("entities: {0}")]
    Entities(String),

    #[error("walk: {0}")]
    Walk(String),

    #[error("other: {0}")]
    Other(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e.to_string())
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::Other(e.to_string())
    }
}

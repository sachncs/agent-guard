//! Error types for agentguard-auth.

use thiserror::Error;

/// Result alias for agentguard-auth fallible operations.
pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    #[error("jwt invalid: {0}")]
    JwtInvalid(String),
    #[error("jwt expired")]
    JwtExpired,
    #[error("jwt audience mismatch: expected {expected}, got {actual}")]
    JwtAudienceMismatch { expected: String, actual: String },
    #[error("jwt issuer mismatch: expected {expected}, got {actual}")]
    JwtIssuerMismatch { expected: String, actual: String },
    #[error("jwt unknown key id: {0}")]
    JwtUnknownKid(String),
    #[error("oidc discovery failed: {0}")]
    OidcDiscovery(String),
    #[error("jwks fetch failed: {0}")]
    JwksFetch(String),
    #[error("dpop invalid: {0}")]
    DpopInvalid(String),
    #[error("dpop htu mismatch: expected {expected}, got {actual}")]
    DpopHtuMismatch { expected: String, actual: String },
    #[error("dpop replay detected (jti={0})")]
    DpopReplay(String),
    #[error("spiffe fetch failed: {0}")]
    SpiffeFetch(String),
    #[error("spiffe identity expired")]
    SpiffeExpired,
    #[error("api key invalid")]
    ApiKeyInvalid,
    #[error("api key expired")]
    ApiKeyExpired,
    #[error("api key revoked")]
    ApiKeyRevoked,
    #[error("clock error: {0}")]
    Clock(String),
    #[error("other: {0}")]
    Other(String),
}

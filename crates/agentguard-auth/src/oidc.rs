//! OIDC discovery (RFC 8414) + JWKS population.
//!
//! `OidcConfig::discover(issuer)` fetches `/.well-known/openid-configuration`
//! and constructs a [`JwtValidator`] pre-populated with keys from the JWKS.

use crate::error::{AuthError, Result};
use crate::jwt::{JwtConfig, JwtValidator};
use serde::Deserialize;

/// OIDC discovery configuration.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    pub algorithms: Vec<crate::key_registry::Algorithm>,
}

impl OidcConfig {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            algorithms: vec![
                crate::key_registry::Algorithm::EdDSA,
                crate::key_registry::Algorithm::RS256,
            ],
        }
    }
}

/// Subset of OIDC discovery metadata relevant to agentguard.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcMetadata {
    pub issuer: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub introspection_endpoint: Option<String>,
}

#[cfg(feature = "jwt")]
impl OidcConfig {
    /// Discover OIDC metadata + JWKS and return a configured [`JwtValidator`].
    pub async fn discover(&self) -> Result<(JwtValidator, OidcMetadata)> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        let body = reqwest::get(&url)
            .await
            .map_err(|e| AuthError::OidcDiscovery(e.to_string()))?
            .text()
            .await
            .map_err(|e| AuthError::OidcDiscovery(e.to_string()))?;
        let meta: OidcMetadata = serde_json::from_str(&body)
            .map_err(|e| AuthError::OidcDiscovery(format!("parse: {}", e)))?;
        let mut cfg = JwtConfig::new(meta.issuer.clone(), self.audience.clone())
            .with_algorithms(self.algorithms.clone())
            .with_jwks_uri(meta.jwks_uri.clone());
        cfg.clock_skew = std::time::Duration::from_secs(60);
        let validator = JwtValidator::new(cfg);
        validator.refresh_jwks().await?;
        Ok((validator, meta))
    }
}

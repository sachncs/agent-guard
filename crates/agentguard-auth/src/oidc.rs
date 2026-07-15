//! OIDC discovery (RFC 8414) + JWKS population.
//!
//! `OidcConfig::discover(issuer)` fetches `/.well-known/openid-configuration`
//! and constructs a [`JwtValidator`] pre-populated with keys from the JWKS.

use crate::error::{AuthError, Result};
use crate::jwt::{JwtConfig, JwtValidator};
use agentguard_core::auth_keys::Algorithm;
use serde::Deserialize;

/// OIDC discovery configuration.
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    pub algorithms: Vec<Algorithm>,
}

impl OidcConfig {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            algorithms: vec![Algorithm::EdDSA, Algorithm::RS256],
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

impl OidcConfig {
    /// Discover OIDC metadata + JWKS and return a configured [`JwtValidator`].
    ///
    /// # Security
    /// Per RFC 8414 §3.3 / OIDC Core §4.3, the `issuer` returned by the
    /// discovery endpoint MUST be exactly equal to the configured issuer.
    /// Without this check, a malicious or MITMed discovery response can swap
    /// the trusted issuer (and the JWKS URL) under the operator's feet.
    pub async fn discover(&self) -> Result<(JwtValidator, OidcMetadata)> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        // Bounded client: 10 s total timeout, 5 s connect, 1 MiB body.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| AuthError::OidcDiscovery(format!("client build: {}", e)))?;
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| AuthError::OidcDiscovery(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::OidcDiscovery(format!(
                "HTTP {}",
                resp.status()
            )));
        }
        let body = resp
            .text()
            .await
            .map_err(|e| AuthError::OidcDiscovery(e.to_string()))?;
        if body.len() > 1_048_576 {
            return Err(AuthError::OidcDiscovery(
                "discovery document exceeds 1 MiB".into(),
            ));
        }
        let meta: OidcMetadata = serde_json::from_str(&body)
            .map_err(|e| AuthError::OidcDiscovery(format!("parse: {}", e)))?;
        // **CRITICAL** issuer pin: the discovered issuer must equal the
        // configured one exactly. (RFC 8414 §3.3)
        if meta.issuer != self.issuer {
            return Err(AuthError::OidcDiscovery(format!(
                "issuer mismatch: configured={} discovered={}",
                self.issuer, meta.issuer
            )));
        }
        let mut cfg = JwtConfig::new(self.issuer.clone(), self.audience.clone())
            .with_algorithms(self.algorithms.clone())
            .with_jwks_uri(meta.jwks_uri.clone());
        cfg.clock_skew = std::time::Duration::from_secs(60);
        let validator = JwtValidator::new(cfg);
        validator.refresh_jwks().await?;
        Ok((validator, meta))
    }
}

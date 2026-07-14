//! SPIFFE/SPIRE X509-SVID verifier (stub for v2.0).
//!
//! In production this would call the SPIFFE Workload API via `spiffe` crate to
//! fetch SVIDs and validate peer certificates. For v2.0 we provide the
//! validation logic with a stub fetcher.

use crate::error::{AuthError, Result};
use std::time::Duration;

/// Validates SPIFFE identities.
pub struct SpiffeValidator {
    pub allowed_trust_domains: Vec<String>,
    pub clock_skew: Duration,
}

impl SpiffeValidator {
    pub fn new(trust_domain: impl Into<String>) -> Self {
        Self {
            allowed_trust_domains: vec![trust_domain.into()],
            clock_skew: Duration::from_secs(60),
        }
    }

    /// Parse and validate a SPIFFE ID string.
    pub fn validate_spiffe_id(&self, id: &str) -> Result<()> {
        let rest = id.strip_prefix("spiffe://").ok_or_else(|| {
            AuthError::SpiffeFetch(format!("invalid SPIFFE ID (missing scheme): {}", id))
        })?;
        let domain = rest.split('/').next().unwrap_or("");
        if !self.allowed_trust_domains.iter().any(|d| d == domain) {
            return Err(AuthError::SpiffeFetch(format!(
                "trust domain {} not in allowlist",
                domain
            )));
        }
        Ok(())
    }

    /// Fetch an SVID from the Workload API. v2.0 stub.
    pub async fn fetch_svid(&self) -> Result<String> {
        Err(AuthError::SpiffeFetch(
            "SPIFFE Workload API integration is a v2.1 feature; configure with `spiffe` crate"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_spiffe_id_passes() {
        let v = SpiffeValidator::new("acme.com");
        v.validate_spiffe_id("spiffe://acme.com/agent/email-bot")
            .unwrap();
    }

    #[test]
    fn wrong_trust_domain_rejected() {
        let v = SpiffeValidator::new("acme.com");
        assert!(v.validate_spiffe_id("spiffe://evil.com/agent").is_err());
    }

    #[test]
    fn missing_scheme_rejected() {
        let v = SpiffeValidator::new("acme.com");
        assert!(v.validate_spiffe_id("acme.com/agent").is_err());
    }
}

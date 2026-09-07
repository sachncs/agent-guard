//! SPIFFE/SPIRE X509-SVID verifier.
//!
//! Validates SPIFFE IDs against an allowlist of trust domains. To fetch
//! SVIDs from a running SPIRE agent, use [`SpiffeValidator::fetch_svid`]
//! which calls the SPIFFE Workload API over the abstract Unix domain
//! socket or HTTPS endpoint configured by the workload.

use crate::error::{AuthError, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Trust domain allowlist and optional workload endpoint.
#[derive(Debug, Clone)]
pub struct SpiffeValidator {
    pub allowed_trust_domains: Vec<String>,
    pub clock_skew: Duration,
    /// Path or URL of the SPIFFE Workload API.
    /// Default: `unix:///run/spire/sockets/agent.sock`.
    pub workload_endpoint: String,
}

impl SpiffeValidator {
    pub fn new(trust_domain: impl Into<String>) -> Self {
        Self {
            allowed_trust_domains: vec![trust_domain.into()],
            clock_skew: Duration::from_secs(60),
            workload_endpoint: "unix:///run/spire/sockets/agent.sock".into(),
        }
    }

    /// Add another trust domain to the allowlist.
    pub fn allow_trust_domain(&mut self, domain: impl Into<String>) -> &mut Self {
        self.allowed_trust_domains.push(domain.into());
        self
    }

    /// Parse and validate a SPIFFE ID string. A SPIFFE ID looks like
    /// `spiffe://<trust-domain>/<workload-path>`.
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

    /// Fetch an SVID from the SPIFFE Workload API.
    ///
    /// Requires the `spiffe` feature (pulls in the SPIFFE Workload API
    /// client). Without the feature, this returns a configuration error
    /// pointing the user at the feature flag.
    #[cfg(feature = "spiffe")]
    pub async fn fetch_svid(&self) -> Result<SpiffeId> {
        use spiffe::WorkloadApiClient;
        // ponytail: bound the connect so a misconfigured endpoint
        // can't park the auth middleware indefinitely. 5 s is generous
        // for a local Unix socket; for HTTPS work, raise in
        // deployment-specific config.
        let connect_fut = WorkloadApiClient::connect_to(&self.workload_endpoint);
        let client = tokio::time::timeout(Duration::from_secs(5), connect_fut)
            .await
            .map_err(|_| {
                AuthError::SpiffeFetch(format!(
                    "timed out connecting to SPIFFE Workload API at {}",
                    self.workload_endpoint
                ))
            })?
            .map_err(|e| AuthError::SpiffeFetch(format!("workload api connect: {}", e)))?;
        let x509_svid = client
            .fetch_x509_svid()
            .await
            .map_err(|e| AuthError::SpiffeFetch(format!("fetch x509-svid: {}", e)))?;
        // ponytail: validate the SVID's expiry window. The previous
        // code skipped this entirely — an expired SVID would have
        // been accepted as long as its SPIFFE ID was in the
        // allowlist.
        let now = chrono::Utc::now();
        let skew =
            chrono::Duration::from_std(self.clock_skew).unwrap_or(chrono::Duration::seconds(0));
        let not_after = *x509_svid.expires_at();
        if not_after + skew < now {
            return Err(AuthError::SpiffeFetch(format!(
                "SVID expired at {}",
                not_after.to_rfc3339()
            )));
        }
        let not_before = *x509_svid.not_before();
        if not_before > now + skew {
            return Err(AuthError::SpiffeFetch(format!(
                "SVID not valid until {}",
                not_before.to_rfc3339()
            )));
        }
        let spiffe_id = x509_svid.spiffe_id().to_string();
        self.validate_spiffe_id(&spiffe_id)?;
        Ok(SpiffeId { id: spiffe_id })
    }

    /// Fetch an SVID stub: returns the trust domain if configured. Useful
    /// for testing and when SPIRE isn't available.
    #[cfg(not(feature = "spiffe"))]
    pub async fn fetch_svid(&self) -> Result<SpiffeId> {
        Err(AuthError::SpiffeFetch(
            "SPIFFE Workload API integration requires the 'spiffe' feature on agentguard-auth"
                .into(),
        ))
    }
}

/// A SPIFFE identity, returned by [`SpiffeValidator::fetch_svid`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpiffeId {
    /// Full SPIFFE ID like `spiffe://acme.com/agent/email-bot`.
    pub id: String,
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

    #[test]
    fn multiple_trust_domains() {
        let mut v = SpiffeValidator::new("acme.com");
        v.allow_trust_domain("partner.com");
        v.validate_spiffe_id("spiffe://acme.com/x").unwrap();
        v.validate_spiffe_id("spiffe://partner.com/y").unwrap();
        assert!(v.validate_spiffe_id("spiffe://other.com/z").is_err());
    }
}

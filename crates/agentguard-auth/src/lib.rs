//! Authentication for agentguard.
//!
//! Implements JWT validation (RFC 7519 + 8725 BCP), OIDC discovery (RFC 8414),
//! API key management, DPoP verification (RFC 9449), and SPIFFE/SPIRE X509-SVID
//! verification.
//!
//! The JOSE primitives (`Algorithm`, `KeyMaterial`, `KeyRegistry`,
//! `parse_alg`) live in `agentguard_core::auth_keys` and are re-exported
//! here for convenience.

pub mod api_key;
pub mod dpop;
pub mod error;
pub mod jti;
pub mod jwt;
pub mod oidc;
pub mod spiffe;

pub use agentguard_core::auth_keys::{parse_alg, Algorithm, KeyMaterial, KeyRegistry};
pub use api_key::{ApiKey, ApiKeyStore};
pub use dpop::DpopVerifier;
pub use error::AuthError;
pub use jti::JtiTracker;
pub use jwt::{JwtConfig, JwtValidator, ValidatedJwt};
pub use oidc::{OidcConfig, OidcMetadata};
pub use spiffe::SpiffeValidator;

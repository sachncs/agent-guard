//! Authentication for agentguard.
//!
//! Implements JWT validation (RFC 7519 + 8725 BCP), OIDC discovery (RFC 8414),
//! API key management, DPoP verification (RFC 9449), and SPIFFE/SPIRE X509-SVID
//! verification.

pub mod api_key;
pub mod dpop;
pub mod error;
pub mod jti;
pub mod jwt;
pub mod key_registry;
pub mod oidc;
pub mod spiffe;

pub use api_key::{ApiKey, ApiKeyStore};
pub use dpop::DpopVerifier;
pub use error::AuthError;
pub use jti::JtiTracker;
pub use jwt::{JwtConfig, JwtValidator, ValidatedJwt};
pub use key_registry::{Algorithm, KeyMaterial, KeyRegistry};
pub use oidc::{OidcConfig, OidcMetadata};
pub use spiffe::SpiffeValidator;

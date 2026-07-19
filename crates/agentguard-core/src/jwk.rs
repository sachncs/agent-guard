//! JWK (JSON Web Key) primitives shared by the JWT and DPoP
//! verifiers.
//!
//! Currently exposes only the RFC 7638 thumbprint for an Ed25519
//! public key, used as the deterministic kid when an IdP doesn't
//! supply one of its own. The two callers (jwt.rs, dpop.rs) used to
//! maintain identical copies of this logic; they now both call
//! [`thumbprint_ed25519`].

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// RFC 7638 JWK thumbprint for an Ed25519 public key.
///
/// Returns the base64url-no-pad SHA-256 of the canonical JSON
/// `{"crv":"<crv>","kty":"OKP","x":"<base64url-x>"}`. The argument
/// `crv` defaults to `"Ed25519"` if the caller passes an empty
/// string; the caller is expected to validate non-default `crv`
/// values upstream.
///
/// # Errors
/// Returns `Err` only if the `x` argument is not valid base64url.
pub fn thumbprint_ed25519(x_b64: &str, crv: &str) -> String {
    let crv = if crv.is_empty() { "Ed25519" } else { crv };
    let canonical = format!(r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#, crv, x_b64);
    let hash = Sha256::digest(canonical.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let x1 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        let x2 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32]);
        assert_ne!(
            thumbprint_ed25519(&x1, "Ed25519"),
            thumbprint_ed25519(&x2, "Ed25519")
        );
        assert_eq!(
            thumbprint_ed25519(&x1, "Ed25519"),
            thumbprint_ed25519(&x1, "Ed25519")
        );
    }

    #[test]
    fn empty_crv_defaults_to_ed25519() {
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        assert_eq!(
            thumbprint_ed25519(&x, ""),
            thumbprint_ed25519(&x, "Ed25519"),
        );
    }
}

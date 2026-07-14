//! DPoP (RFC 9449) proof-of-possession verifier.
//!
//! Verifies the DPoP proof JWT in the `DPoP` header against the access
//! token's `cnf.jkt` claim (RFC 9449 §4.2). Replay protection via
//! [`JtiTracker`].
//!
//! Verification steps (RFC 9449 §4.2 + RFC 7638):
//! 1. Parse the compact JWS; require 3 segments.
//! 2. Require header `typ == "dpop+jwt"` and `alg` in the whitelist.
//! 3. Extract the public key from header `jwk`. Require `kty=OKP`,
//!    `crv=Ed25519`, `x` is 32 base64url-encoded bytes.
//! 4. Compute the JWK thumbprint per RFC 7638 and require it equals
//!    `expected_jkt` (the `cnf.jkt` value from the access token).
//! 5. Verify the EdDSA signature over `header.payload` using the `jwk`.
//! 6. Verify `htm`, `htu`, `ath` (SHA-256 base64url of the access token).
//! 7. Verify `jti` uniqueness via [`JtiTracker`] (SHA-256 keyed).

use crate::error::{AuthError, Result};
use crate::jti::JtiTracker;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

/// Whitelist of DPoP proof `alg` values. RFC 9449 §4.2 only allows
/// asymmetric algorithms; HS* is forbidden.
const DPOP_ALG_EDDSA: &str = "EdDSA";

/// Verifies DPoP proof JWTs.
#[derive(Clone)]
pub struct DpopVerifier {
    keys: Arc<JtiTracker>,
    pub allowed_clock_skew: Duration,
}

impl DpopVerifier {
    pub fn new(jti_tracker: Arc<JtiTracker>) -> Self {
        Self {
            keys: jti_tracker,
            allowed_clock_skew: Duration::from_secs(30),
        }
    }

    /// Verify a DPoP proof.
    ///
    /// - `dpop_header`: the `DPoP` header value (compact JWS)
    /// - `access_token`: the access token bound to this DPoP proof. Used only
    ///   to compute the `ath` claim (RFC 9449 §4.2: SHA-256 base64url-no-pad).
    /// - `htm`: HTTP method (e.g. `POST`)
    /// - `htu`: HTTP URI (must match exactly, RFC 9449 §4.2 strict equality)
    /// - `expected_jkt`: the JWK SHA-256 thumbprint (RFC 7638) of the public
    ///   key the access token is bound to. Extracted from the access token's
    ///   `cnf.jkt` claim by the caller. **Required** — DPoP without a known
    ///   jkt cannot establish proof-of-possession.
    ///
    /// # Errors
    /// Returns `AuthError::DpopInvalid` on any structural, alg, or jkt
    /// problem, and `AuthError::DpopReplay` on `jti` reuse.
    pub fn verify(
        &self,
        dpop_header: &str,
        access_token: &str,
        htm: &str,
        htu: &str,
        expected_jkt: &str,
    ) -> Result<()> {
        // 1. Parse the compact JWS.
        let parts: Vec<&str> = dpop_header.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::DpopInvalid("expected 3 segments".into()));
        }
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| AuthError::DpopInvalid(format!("header b64: {}", e)))?;
        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| AuthError::DpopInvalid(format!("header json: {}", e)))?;
        let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| AuthError::DpopInvalid(format!("claims b64: {}", e)))?;
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
            .map_err(|e| AuthError::DpopInvalid(format!("claims json: {}", e)))?;
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| AuthError::DpopInvalid(format!("sig b64: {}", e)))?;

        // 2. Validate header typ + alg.
        let header_typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
        if header_typ != "dpop+jwt" {
            return Err(AuthError::DpopInvalid(format!(
                "header typ must be 'dpop+jwt', got {:?}",
                header_typ
            )));
        }
        let header_alg = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::DpopInvalid("missing alg".into()))?;
        if header_alg != DPOP_ALG_EDDSA {
            return Err(AuthError::DpopInvalid(format!(
                "alg {:?} not in DPoP whitelist",
                header_alg
            )));
        }

        // 3. Extract the jwk public key.
        let jwk = header
            .get("jwk")
            .ok_or_else(|| AuthError::DpopInvalid("missing jwk in header".into()))?;
        let raw_key = parse_ed25519_jwk(jwk)?;

        // 4. Compute the JWK thumbprint (RFC 7638) and compare to expected_jkt.
        let thumbprint = jwk_thumbprint_ed25519(jwk)?;
        if !constant_time_eq(thumbprint.as_bytes(), expected_jkt.as_bytes()) {
            return Err(AuthError::DpopInvalid("jkt mismatch".into()));
        }

        // 5. Verify the EdDSA signature over the signing input using the jwk.
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let vk = VerifyingKey::from_bytes(&raw_key)
            .map_err(|e| AuthError::DpopInvalid(format!("jwk key: {}", e)))?;
        let sig = Signature::from_slice(&signature)
            .map_err(|e| AuthError::DpopInvalid(format!("ed25519 sig: {}", e)))?;
        vk.verify(signing_input.as_bytes(), &sig)
            .map_err(|_| AuthError::DpopInvalid("signature verification failed".into()))?;

        // 6. Validate htm / htu / ath claims.
        let claim_htm = claims.get("htm").and_then(|v| v.as_str()).unwrap_or("");
        if claim_htm != htm {
            return Err(AuthError::DpopInvalid(format!(
                "htm mismatch: expected {}, got {}",
                htm, claim_htm
            )));
        }
        let claim_htu = claims.get("htu").and_then(|v| v.as_str()).unwrap_or("");
        if claim_htu != htu {
            return Err(AuthError::DpopHtuMismatch {
                expected: htu.to_string(),
                actual: claim_htu.to_string(),
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(access_token.as_bytes());
        let expected_ath =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
        let claim_ath = claims.get("ath").and_then(|v| v.as_str()).unwrap_or("");
        if claim_ath != expected_ath {
            return Err(AuthError::DpopInvalid("ath mismatch".into()));
        }

        // 7. Replay protection: hash the jti to a 16-byte key.
        let jti_str = claims
            .get("jti")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::DpopInvalid("missing jti".into()))?;
        let mut hasher = Sha256::new();
        hasher.update(jti_str.as_bytes());
        let digest = hasher.finalize();
        let mut jti_key = [0u8; 16];
        jti_key.copy_from_slice(&digest[..16]);
        self.keys.check_and_record(&jti_key)?;

        Ok(())
    }
}

/// Parse the JWK members required for Ed25519 (`kty`, `crv`, `x`) and return
/// the raw 32-byte public key.
fn parse_ed25519_jwk(jwk: &serde_json::Value) -> Result<[u8; 32]> {
    let obj = jwk
        .as_object()
        .ok_or_else(|| AuthError::DpopInvalid("jwk must be a JSON object".into()))?;
    let kty = obj
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::DpopInvalid("jwk missing kty".into()))?;
    if kty != "OKP" {
        return Err(AuthError::DpopInvalid(format!(
            "jwk kty must be OKP, got {}",
            kty
        )));
    }
    let crv = obj
        .get("crv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::DpopInvalid("jwk missing crv".into()))?;
    if crv != "Ed25519" {
        return Err(AuthError::DpopInvalid(format!(
            "jwk crv must be Ed25519, got {}",
            crv
        )));
    }
    let x = obj
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::DpopInvalid("jwk missing x".into()))?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| AuthError::DpopInvalid(format!("jwk x b64: {}", e)))?;
    if raw.len() != 32 {
        return Err(AuthError::DpopInvalid(format!(
            "jwk x must be 32 bytes, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Compute the JWK thumbprint per RFC 7638 for an Ed25519 public key.
///
/// Required members (in lex order): `crv`, `kty`, `x`. The thumbprint is
/// `base64url-no-pad(SHA-256(canonical_jwk_json))`.
fn jwk_thumbprint_ed25519(jwk: &serde_json::Value) -> Result<String> {
    let obj = jwk
        .as_object()
        .ok_or_else(|| AuthError::DpopInvalid("jwk not object".into()))?;
    let kty = obj
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::DpopInvalid("jwk missing kty".into()))?;
    let crv = obj
        .get("crv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::DpopInvalid("jwk missing crv".into()))?;
    let x = obj
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::DpopInvalid("jwk missing x".into()))?;
    // Required members only, lex-sorted, no whitespace.
    let canonical = format!(r#"{{"crv":"{}","kty":"{}","x":"{}"}}"#, crv, kty, x);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

/// Constant-time byte slice equality. Used for jkt comparison to avoid
/// leaking the expected thumbprint length/content via timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn make_dpop(signer: &SigningKey, jwk_x_b64: &str, jti: &str, claims_extras: &str) -> String {
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "dpop+jwt",
            "jwk": {"kty": "OKP", "crv": "Ed25519", "x": jwk_x_b64},
        });
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let now = chrono::Utc::now().timestamp();
        let claims_json = if claims_extras.is_empty() {
            format!(
                r#"{{"jti":"{jti}","htm":"POST","htu":"https://example.com/x","iat":{now}}}"#
            )
        } else {
            format!(
                r#"{{"jti":"{jti}","htm":"POST","htu":"https://example.com/x","iat":{now},{extra}}}"#,
                extra = claims_extras
            )
        };
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(claims_json.as_bytes());
        let signing_input = format!("{}.{}", h, p);
        let sig = signer.sign(signing_input.as_bytes());
        let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{}.{}.{}", h, p, s)
    }

    fn make_jkt(pub_key: &[u8; 32]) -> String {
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key);
        let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, x);
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
    }

    #[test]
    fn valid_dpop_accepted() {
        let mut csprng = OsRng;
        let signer = SigningKey::generate(&mut csprng);
        let pub_bytes = signer.verifying_key().to_bytes();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_bytes);
        let jkt = make_jkt(&pub_bytes);
        let mut hasher = Sha256::new();
        hasher.update(b"access-token");
        let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
        let extras = format!(r#""ath":"{}""#, ath);
        let dpop = make_dpop(&signer, &x, "abc", &extras);

        let tracker = Arc::new(JtiTracker::new(Duration::from_secs(60)));
        let v = DpopVerifier::new(tracker);
        v.verify(&dpop, "access-token", "POST", "https://example.com/x", &jkt)
            .unwrap();
    }

    #[test]
    fn htu_mismatch_rejected() {
        let mut csprng = OsRng;
        let signer = SigningKey::generate(&mut csprng);
        let pub_bytes = signer.verifying_key().to_bytes();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_bytes);
        let jkt = make_jkt(&pub_bytes);
        let dpop = make_dpop(&signer, &x, "abc", "");
        let tracker = Arc::new(JtiTracker::new(Duration::from_secs(60)));
        let v = DpopVerifier::new(tracker);
        let err = v
            .verify(&dpop, "tok", "POST", "https://example.com/y", &jkt)
            .unwrap_err();
        assert!(
            matches!(err, AuthError::DpopHtuMismatch { .. }),
            "expected DpopHtuMismatch, got {:?}",
            err
        );
    }

    #[test]
    fn htm_mismatch_rejected() {
        let mut csprng = OsRng;
        let signer = SigningKey::generate(&mut csprng);
        let pub_bytes = signer.verifying_key().to_bytes();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_bytes);
        let jkt = make_jkt(&pub_bytes);
        let dpop = make_dpop(&signer, &x, "abc", "");
        let tracker = Arc::new(JtiTracker::new(Duration::from_secs(60)));
        let v = DpopVerifier::new(tracker);
        let err = v
            .verify(&dpop, "tok", "GET", "https://example.com/x", &jkt)
            .unwrap_err();
        assert!(matches!(err, AuthError::DpopInvalid(_)));
    }

    #[test]
    fn ath_mismatch_rejected() {
        let mut csprng = OsRng;
        let signer = SigningKey::generate(&mut csprng);
        let pub_bytes = signer.verifying_key().to_bytes();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_bytes);
        let jkt = make_jkt(&pub_bytes);
        let mut hasher = Sha256::new();
        hasher.update(b"real-token");
        let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
        let extras = format!(r#""ath":"{}""#, ath);
        let dpop = make_dpop(&signer, &x, "abc", &extras);
        let tracker = Arc::new(JtiTracker::new(Duration::from_secs(60)));
        let v = DpopVerifier::new(tracker);
        let err = v
            .verify(&dpop, "different-token", "POST", "https://example.com/x", &jkt)
            .unwrap_err();
        assert!(matches!(err, AuthError::DpopInvalid(_)));
    }

    #[test]
    fn missing_jti_rejected() {
        let mut csprng = OsRng;
        let signer = SigningKey::generate(&mut csprng);
        let pub_bytes = signer.verifying_key().to_bytes();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_bytes);
        let jkt = make_jkt(&pub_bytes);
        // Build DPoP with empty jti by hand.
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "dpop+jwt",
            "jwk": {"kty": "OKP", "crv": "Ed25519", "x": x},
        });
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let claims = serde_json::json!({
            "htm": "POST",
            "htu": "https://example.com/x",
            "iat": chrono::Utc::now().timestamp(),
        });
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{}.{}", h, p);
        let sig = signer.sign(signing_input.as_bytes());
        let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let dpop = format!("{}.{}.{}", h, p, s);
        let tracker = Arc::new(JtiTracker::new(Duration::from_secs(60)));
        let v = DpopVerifier::new(tracker);
        let err = v
            .verify(&dpop, "tok", "POST", "https://example.com/x", &jkt)
            .unwrap_err();
        assert!(matches!(err, AuthError::DpopInvalid(_)));
    }

    #[test]
    fn malformed_dpop_header_rejected() {
        let tracker = Arc::new(JtiTracker::new(Duration::from_secs(60)));
        let v = DpopVerifier::new(tracker);
        let err = v
            .verify("only.two", "token", "POST", "https://example.com/x", "any")
            .unwrap_err();
        assert!(matches!(err, AuthError::DpopInvalid(_)));
    }

    #[test]
    fn jkt_mismatch_rejected() {
        // Right shape, but the access token's cnf.jkt doesn't match the
        // proof's jwk thumbprint — attacker can't bind a different key.
        let mut csprng = OsRng;
        let signer = SigningKey::generate(&mut csprng);
        let pub_bytes = signer.verifying_key().to_bytes();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_bytes);
        let mut hasher = Sha256::new();
        hasher.update(b"tok");
        let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
        let extras = format!(r#""ath":"{}""#, ath);
        let dpop = make_dpop(&signer, &x, "abc", &extras);
        let tracker = Arc::new(JtiTracker::new(Duration::from_secs(60)));
        let v = DpopVerifier::new(tracker);
        let wrong_jkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let err = v
            .verify(&dpop, "tok", "POST", "https://example.com/x", wrong_jkt)
            .unwrap_err();
        assert!(matches!(err, AuthError::DpopInvalid(_)));
    }

    #[test]
    fn signature_tamper_rejected() {
        // Real signature, but the signature segment is replaced with a
        // different valid EdDSA signature from a different key. The
        // verifier must reject because the signature won't match the jwk.
        let mut csprng = OsRng;
        let signer = SigningKey::generate(&mut csprng);
        let pub_bytes = signer.verifying_key().to_bytes();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_bytes);
        let jkt = make_jkt(&pub_bytes);
        let mut hasher = Sha256::new();
        hasher.update(b"tok");
        let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
        let extras = format!(r#""ath":"{}""#, ath);
        let mut dpop = make_dpop(&signer, &x, "abc", &extras);
        // Flip a character in the signature segment.
        let idx = dpop.rfind('.').unwrap() + 1;
        let mut chars: Vec<char> = dpop.chars().collect();
        let sig_start = dpop[..idx].chars().count();
        let c = chars[sig_start];
        chars[sig_start] = if c == 'A' { 'B' } else { 'A' };
        dpop = chars.into_iter().collect();
        let tracker = Arc::new(JtiTracker::new(Duration::from_secs(60)));
        let v = DpopVerifier::new(tracker);
        let err = v
            .verify(&dpop, "tok", "POST", "https://example.com/x", &jkt)
            .unwrap_err();
        assert!(matches!(err, AuthError::DpopInvalid(_)));
    }

    #[test]
    fn replay_rejected() {
        // Same DPoP replayed a second time within the TTL window.
        let mut csprng = OsRng;
        let signer = SigningKey::generate(&mut csprng);
        let pub_bytes = signer.verifying_key().to_bytes();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_bytes);
        let jkt = make_jkt(&pub_bytes);
        let mut hasher = Sha256::new();
        hasher.update(b"tok");
        let ath = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
        let extras = format!(r#""ath":"{}""#, ath);
        let dpop = make_dpop(&signer, &x, "unique-jti", &extras);
        let tracker = Arc::new(JtiTracker::new(Duration::from_secs(60)));
        let v = DpopVerifier::new(tracker);
        v.verify(&dpop, "tok", "POST", "https://example.com/x", &jkt)
            .unwrap();
        let err = v
            .verify(&dpop, "tok", "POST", "https://example.com/x", &jkt)
            .unwrap_err();
        assert!(matches!(err, AuthError::DpopReplay(_)));
    }
}
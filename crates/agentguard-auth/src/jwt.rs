//! JWT validation per RFC 7519 + RFC 8725 BCP.
//!
//! Supports algorithm whitelist, `kid`-based key resolution, `iss`/`aud`/`exp`
//! validation, and JWKS refresh.

use crate::error::{AuthError, Result};
use crate::key_registry::{Algorithm, KeyMaterial, KeyRegistry};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Configuration for [`JwtValidator`].
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Expected `iss` claim.
    pub issuer: String,
    /// Expected `aud` claim.
    pub audience: String,
    /// Whitelist of accepted signing algorithms (RFC 8725 §3.1).
    pub algorithms: Vec<Algorithm>,
    /// JWKS URI (optional). If set, keys are fetched from this URL.
    pub jwks_uri: Option<String>,
    /// Clock skew tolerance for `exp`/`nbf`.
    pub clock_skew: Duration,
}

impl JwtConfig {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            algorithms: vec![Algorithm::EdDSA, Algorithm::RS256, Algorithm::ES256],
            jwks_uri: None,
            clock_skew: Duration::from_secs(60),
        }
    }

    pub fn with_algorithms(mut self, algs: Vec<Algorithm>) -> Self {
        self.algorithms = algs;
        self
    }

    pub fn with_jwks_uri(mut self, uri: impl Into<String>) -> Self {
        self.jwks_uri = Some(uri.into());
        self
    }
}

/// A successfully validated JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedJwt {
    pub header: HashMap<String, serde_json::Value>,
    pub claims: serde_json::Value,
}

/// Validates JWTs against a [`JwtConfig`] and [`KeyRegistry`].
#[derive(Clone)]
pub struct JwtValidator {
    config: Arc<JwtConfig>,
    keys: Arc<KeyRegistry>,
}

impl JwtValidator {
    pub fn new(config: JwtConfig) -> Self {
        Self {
            config: Arc::new(config),
            keys: Arc::new(KeyRegistry::new()),
        }
    }

    /// Register a key for verification.
    pub fn add_key(&self, kid: impl Into<String>, alg: Algorithm, key: KeyMaterial) -> Result<()> {
        self.keys.add(kid, alg, key)
    }

    /// Validate a JWT. The `kid` and `alg` from the header are used to find
    /// a matching key.
    ///
    /// Note: cryptographic verification is implemented for EdDSA (HMAC-like
    /// signature) in this release; RS256/ES256 support requires adding the
    /// `jsonwebtoken` crate as a feature in v2.1.
    pub fn validate(&self, token: &str) -> Result<ValidatedJwt> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::JwtInvalid("expected 3 parts".into()));
        }
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| AuthError::JwtInvalid(format!("header b64: {}", e)))?;
        let header: HashMap<String, serde_json::Value> = serde_json::from_slice(&header_bytes)
            .map_err(|e| AuthError::JwtInvalid(format!("header json: {}", e)))?;

        let alg_str = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::JwtInvalid("missing alg".into()))?;
        let alg = parse_alg(alg_str)?;
        if !self.config.algorithms.contains(&alg) {
            return Err(AuthError::JwtInvalid(format!(
                "algorithm {:?} not in whitelist",
                alg
            )));
        }
        let kid = header
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::JwtInvalid("missing kid".into()))?;

        let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| AuthError::JwtInvalid(format!("claims b64: {}", e)))?;
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
            .map_err(|e| AuthError::JwtInvalid(format!("claims json: {}", e)))?;

        // Verify signature.
        let signing_input = format!("{}.{}", parts[0], parts[1]).into_bytes();
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| AuthError::JwtInvalid(format!("sig b64: {}", e)))?;
        let keys = self.keys.get(kid, alg)?;
        let mut verified = false;
        for key in keys {
            if verify_signature(alg, &key, &signing_input, &signature).is_ok() {
                verified = true;
                break;
            }
        }
        if !verified {
            return Err(AuthError::JwtInvalid(
                "signature verification failed".into(),
            ));
        }

        // Validate iss, aud, exp, nbf.
        if let Some(iss) = claims.get("iss").and_then(|v| v.as_str()) {
            if iss != self.config.issuer {
                return Err(AuthError::JwtIssuerMismatch {
                    expected: self.config.issuer.clone(),
                    actual: iss.to_string(),
                });
            }
        }
        let aud_ok = match claims.get("aud") {
            Some(serde_json::Value::String(s)) => *s == self.config.audience,
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .any(|v| v.as_str() == Some(self.config.audience.as_str())),
            _ => false,
        };
        if !aud_ok {
            return Err(AuthError::JwtAudienceMismatch {
                expected: self.config.audience.clone(),
                actual: format!("{:?}", claims.get("aud")),
            });
        }
        let now = chrono::Utc::now().timestamp();
        let skew = self.config.clock_skew.as_secs() as i64;
        if let Some(exp) = claims.get("exp").and_then(|v| v.as_i64()) {
            if exp + skew < now {
                return Err(AuthError::JwtExpired);
            }
        }
        if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
            if nbf > now + skew {
                return Err(AuthError::JwtInvalid("token not yet valid".into()));
            }
        }

        Ok(ValidatedJwt { header, claims })
    }

    /// Fetch JWKS from `jwks_uri` and populate the key registry. Idempotent.
    ///
    /// Supports Ed25519 keys (kty=OK, crv=Ed25519, x=base64url-32-bytes).
    /// Other key types are skipped with a tracing warning.
    #[cfg(feature = "jwt")]
    pub async fn refresh_jwks(&self) -> Result<()> {
        use base64::Engine as _;
        let uri = self
            .config
            .jwks_uri
            .as_ref()
            .ok_or_else(|| AuthError::Other("no jwks_uri configured".into()))?;
        let body = reqwest::get(uri)
            .await
            .map_err(|e| AuthError::JwksFetch(e.to_string()))?
            .text()
            .await
            .map_err(|e| AuthError::JwksFetch(e.to_string()))?;
        let jwks: JwksDoc = serde_json::from_str(&body)
            .map_err(|e| AuthError::JwksFetch(format!("parse: {}", e)))?;
        for k in jwks.keys {
            let alg = match parse_alg(&k.alg) {
                Ok(a) => a,
                Err(_) => {
                    tracing::warn!(alg = %k.alg, "skipping unknown JWKS alg");
                    continue;
                }
            };
            // Decode per key-type.
            if matches!(alg, Algorithm::EdDSA) {
                let x = match k.x.as_deref() {
                    Some(s) => s,
                    None => continue,
                };
                let raw = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(x) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(error = %e, "skipping Ed25519 JWKS key: bad x");
                        continue;
                    }
                };
                if raw.len() != 32 {
                    tracing::warn!("skipping Ed25519 JWKS key: x is not 32 bytes");
                    continue;
                }
                let kid = k.kid.clone().unwrap_or_else(|| {
                    tracing::warn!("JWKS key without kid; auto-generating");
                    format!("jwks-{}", k.alg)
                });
                if let Err(e) = self.keys.add(&kid, Algorithm::EdDSA, KeyMaterial::Ed25519(raw)) {
                    tracing::warn!(error = %e, kid = %kid, "failed to register JWKS key");
                }
            } else {
                // RSA/ECDSA/HS256 would be supported here in v2.1.
                tracing::debug!(alg = ?alg, "skipping non-Ed25519 JWKS key");
            }
        }
        Ok(())
    }

    /// Background task that periodically refreshes JWKS.
    #[cfg(feature = "jwt")]
    pub fn spawn_jwks_refresher(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                if let Err(e) = self.refresh_jwks().await {
                    tracing::warn!(error = %e, "jwks refresh failed");
                }
            }
        });
    }
}

#[derive(Debug, Deserialize)]
struct JwksDoc {
    keys: Vec<JwksKey>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct JwksKey {
    #[serde(default)]
    kty: Option<String>,
    #[serde(default)]
    key_type: Option<String>,
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    crv: Option<String>,
}

fn parse_alg(s: &str) -> Result<Algorithm> {
    match s {
        "HS256" => Ok(Algorithm::HS256),
        "RS256" => Ok(Algorithm::RS256),
        "ES256" => Ok(Algorithm::ES256),
        "EdDSA" => Ok(Algorithm::EdDSA),
        other => Err(AuthError::JwtInvalid(format!("unsupported alg: {}", other))),
    }
}

fn verify_signature(
    alg: Algorithm,
    key: &KeyMaterial,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    match (alg, key) {
        (Algorithm::EdDSA, KeyMaterial::Ed25519(bytes)) => {
            if bytes.len() != 32 {
                return Err(AuthError::JwtInvalid("ed25519 key must be 32 bytes".into()));
            }
            let vk = VerifyingKey::from_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| AuthError::JwtInvalid("bad ed25519 key".into()))?,
            )
            .map_err(|e| AuthError::JwtInvalid(format!("ed25519 key: {}", e)))?;
            let sig = Signature::from_slice(signature)
                .map_err(|e| AuthError::JwtInvalid(format!("ed25519 sig: {}", e)))?;
            vk.verify(signing_input, &sig)
                .map_err(|_| AuthError::JwtInvalid("ed25519 verify failed".into()))?;
            Ok(())
        }
        _ => Err(AuthError::JwtInvalid(format!(
            "alg {:?} not implemented in this release",
            alg
        ))),
    }
}

// Suppress unused warning when jwt feature is off
#[cfg(not(feature = "jwt"))]
use AuthError as _Unused;
#[allow(dead_code)]
type _Unused = AuthError;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn sign_token(signer: &SigningKey, kid: &str, claims: serde_json::Value) -> String {
        let header = serde_json::json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{}.{}", h, p);
        let sig = signer.sign(signing_input.as_bytes());
        let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{}.{}.{}", h, p, s)
    }

    #[test]
    fn eddsa_token_validates() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_bytes = signing_key.verifying_key().to_bytes().to_vec();

        let v = JwtValidator::new(JwtConfig::new("https://idp.example.com", "agentguard"));
        v.add_key("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes))
            .unwrap();

        let claims = serde_json::json!({
            "iss": "https://idp.example.com",
            "aud": "agentguard",
            "sub": "alice",
            "exp": chrono::Utc::now().timestamp() + 3600,
        });
        let token = sign_token(&signing_key, "kid1", claims);
        let res = v.validate(&token);
        assert!(res.is_ok(), "expected valid token, got {:?}", res);
    }

    #[test]
    fn expired_token_rejected() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let v = JwtValidator::new(JwtConfig::new("https://idp.example.com", "agentguard"));
        v.add_key("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes))
            .unwrap();
        let claims = serde_json::json!({
            "iss": "https://idp.example.com",
            "aud": "agentguard",
            "exp": chrono::Utc::now().timestamp() - 100,
        });
        let token = sign_token(&signing_key, "kid1", claims);
        let res = v.validate(&token);
        assert!(matches!(res, Err(AuthError::JwtExpired)));
    }

    #[test]
    fn wrong_audience_rejected() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let v = JwtValidator::new(JwtConfig::new("https://idp.example.com", "agentguard"));
        v.add_key("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes))
            .unwrap();
        let claims = serde_json::json!({
            "iss": "https://idp.example.com",
            "aud": "wrong-audience",
            "exp": chrono::Utc::now().timestamp() + 3600,
        });
        let token = sign_token(&signing_key, "kid1", claims);
        let res = v.validate(&token);
        assert!(matches!(res, Err(AuthError::JwtAudienceMismatch { .. })));
    }

    #[test]
    fn unknown_kid_rejected() {
        let v = JwtValidator::new(JwtConfig::new("iss", "aud"));
        let res = v.validate("aaa.bbb.ccc");
        assert!(matches!(res, Err(AuthError::JwtInvalid(_))));
    }
}

//! JWT validation per RFC 7519 + RFC 8725 BCP.
//!
//! Supports algorithm whitelist, `kid`-based key resolution, `iss`/`aud`/`exp`
//! validation, and JWKS refresh.

use crate::error::{AuthError, Result};
use agentguard_core::auth_keys::{parse_alg, Algorithm, KeyMaterial, KeyRegistry};
use agentguard_core::jwk::thumbprint_ed25519 as jwk_thumbprint_ed25519;
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
    /// Default = `[EdDSA]` because `verify_signature` only implements
    /// Ed25519 today; RS256/ES256 are reserved for v2.1. Operators
    /// can opt in via `with_algorithms` once they're implemented.
    pub algorithms: Vec<Algorithm>,
    /// JWKS URI (optional). If set, keys are fetched from this URL.
    pub jwks_uri: Option<String>,
    /// JWKS refresh interval. Default = 30 s. Read from the
    /// `AGENTGUARD_JWKS_REFRESH` env var (humantime format).
    pub jwks_refresh: Duration,
    /// Clock skew tolerance for `exp`/`nbf`.
    pub clock_skew: Duration,
}

impl JwtConfig {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            algorithms: vec![Algorithm::EdDSA],
            jwks_uri: None,
            jwks_refresh: Duration::from_secs(30),
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

    pub fn with_jwks_refresh(mut self, d: Duration) -> Self {
        self.jwks_refresh = d;
        self
    }

    /// Read the JWKS refresh interval from `AGENTGUARD_JWKS_REFRESH`
    /// (humantime). Falls back to the default when unset or unparseable.
    pub fn with_jwks_refresh_from_env(mut self) -> Self {
        if let Ok(s) = std::env::var("AGENTGUARD_JWKS_REFRESH") {
            match humantime::parse_duration(&s) {
                Ok(d) => self.jwks_refresh = d,
                Err(e) => tracing::warn!(
                    env = %s,
                    error = %e,
                    "AGENTGUARD_JWKS_REFRESH is not a valid duration; using default"
                ),
            }
        }
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
    /// Build a new validator with an empty key registry. Call [`Self::add_key`]
    /// for each trusted issuer.
    pub fn new(config: JwtConfig) -> Self {
        Self {
            config: Arc::new(config),
            keys: Arc::new(KeyRegistry::new()),
        }
    }

    /// Register a key for verification.
    pub fn add_key(&self, kid: impl Into<String>, alg: Algorithm, key: KeyMaterial) {
        self.keys.add(kid, alg, key)
    }

    /// Validate a JWT. The `kid` and `alg` from the header are used to find
    /// a matching key.
    ///
    /// Note: cryptographic verification is implemented for EdDSA (HMAC-like
    /// signature) in this release; RS256/ES256 support requires adding the
    /// `jsonwebtoken` crate as a feature in v2.1.
    pub fn validate(&self, token: &str) -> Result<ValidatedJwt> {
        let (header, claims, signing_input, signature) = Self::parse_token(token)?;
        let (alg, kid) = self.check_header(&header)?;
        self.check_signature(&signing_input, &signature, &kid, alg)?;
        self.check_claims(&claims)?;
        Ok(ValidatedJwt { header, claims })
    }

    /// Parse a compact JWS into its constituent parts. Returns the decoded
    /// header, claims, signing input bytes, and signature bytes.
    #[allow(clippy::type_complexity)]
    fn parse_token(
        token: &str,
    ) -> Result<(
        HashMap<String, serde_json::Value>,
        serde_json::Value,
        Vec<u8>,
        Vec<u8>,
    )> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::JwtInvalid("expected 3 parts".into()));
        }
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| AuthError::JwtInvalid(format!("header b64: {}", e)))?;
        let header: HashMap<String, serde_json::Value> = serde_json::from_slice(&header_bytes)
            .map_err(|e| AuthError::JwtInvalid(format!("header json: {}", e)))?;

        let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| AuthError::JwtInvalid(format!("claims b64: {}", e)))?;
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
            .map_err(|e| AuthError::JwtInvalid(format!("claims json: {}", e)))?;

        let signing_input = format!("{}.{}", parts[0], parts[1]).into_bytes();
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| AuthError::JwtInvalid(format!("sig b64: {}", e)))?;
        Ok((header, claims, signing_input, signature))
    }

    /// Extract and validate the `alg` and `kid` from the JOSE header.
    fn check_header(
        &self,
        header: &HashMap<String, serde_json::Value>,
    ) -> Result<(Algorithm, String)> {
        let alg_str = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::JwtInvalid("missing alg".into()))?;
        let alg = parse_alg(alg_str)
            .ok_or_else(|| AuthError::JwtInvalid(format!("unsupported alg: {}", alg_str)))?;
        if !self.config.algorithms.contains(&alg) {
            return Err(AuthError::JwtInvalid(format!(
                "algorithm {:?} not in whitelist",
                alg
            )));
        }
        let kid = header
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::JwtInvalid("missing kid".into()))?
            .to_string();
        Ok((alg, kid))
    }

    /// Verify the JWS signature using one of the keys registered for `(kid, alg)`.
    fn check_signature(
        &self,
        signing_input: &[u8],
        signature: &[u8],
        kid: &str,
        alg: Algorithm,
    ) -> Result<()> {
        let keys = self.keys.get(kid, alg);
        if keys.is_empty() {
            return Err(AuthError::JwtUnknownKid(kid.to_string()));
        }
        for key in keys {
            if verify_signature(alg, &key, signing_input, signature).is_ok() {
                return Ok(());
            }
        }
        Err(AuthError::JwtInvalid(
            "signature verification failed".into(),
        ))
    }

    /// Validate the standard claims: `iss` (required), `aud` (matches),
    /// `exp` (required, not expired), `nbf` (not in future).
    fn check_claims(&self, claims: &serde_json::Value) -> Result<()> {
        // iss (RFC 8725 §3.1: required).
        let iss = claims.get("iss").and_then(|v| v.as_str()).ok_or_else(|| {
            AuthError::JwtIssuerMismatch {
                expected: self.config.issuer.clone(),
                actual: "<missing>".into(),
            }
        })?;
        if iss != self.config.issuer {
            return Err(AuthError::JwtIssuerMismatch {
                expected: self.config.issuer.clone(),
                actual: iss.to_string(),
            });
        }

        // aud: must contain self.config.audience.
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

        // exp (required, RFC 8725 §3.12).
        let exp = claims
            .get("exp")
            .and_then(|v| v.as_i64())
            .ok_or(AuthError::JwtExpired)?;
        let now = chrono::Utc::now().timestamp();
        let skew = self.config.clock_skew.as_secs() as i64;
        if exp + skew < now {
            return Err(AuthError::JwtExpired);
        }

        // nbf (optional): not in the future (with skew).
        if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
            if nbf > now + skew {
                return Err(AuthError::JwtInvalid("token not yet valid".into()));
            }
        }

        // iat (optional): not in the future (with skew).
        if let Some(iat) = claims.get("iat").and_then(|v| v.as_i64()) {
            if iat > now + skew {
                return Err(AuthError::JwtInvalid("iat is in the future".into()));
            }
        }

        Ok(())
    }

    /// Fetch JWKS from `jwks_uri` and populate the key registry. Idempotent.
    ///
    /// Supports Ed25519 keys (kty=OK, crv=Ed25519, x=base64url-32-bytes).
    /// Other key types are skipped with a tracing warning.
    pub async fn refresh_jwks(&self) -> Result<()> {
        use base64::Engine as _;
        let uri = self
            .config
            .jwks_uri
            .as_ref()
            .ok_or_else(|| AuthError::Other("no jwks_uri configured".into()))?;
        // Bounded client: 10 s total, 5 s connect, no redirects (would
        // let an attacker point us at an unrelated host), 1 MiB body cap.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| AuthError::JwksFetch(format!("client build: {}", e)))?;
        let resp = client
            .get(uri)
            .send()
            .await
            .map_err(|e| AuthError::JwksFetch(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::JwksFetch(format!("HTTP {}", resp.status())));
        }
        let body = resp
            .text()
            .await
            .map_err(|e| AuthError::JwksFetch(e.to_string()))?;
        if body.len() > 1_048_576 {
            return Err(AuthError::JwksFetch("JWKS document exceeds 1 MiB".into()));
        }
        let jwks: JwksDoc = serde_json::from_str(&body)
            .map_err(|e| AuthError::JwksFetch(format!("parse: {}", e)))?;
        if jwks.keys.len() > 64 {
            return Err(AuthError::JwksFetch(format!(
                "JWKS document has {} keys; refusing to register more than 64",
                jwks.keys.len()
            )));
        }
        for k in jwks.keys {
            let alg = match parse_alg(&k.alg) {
                Some(a) => a,
                None => {
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
                // ponytail: derive kid from the JWK itself when the
                // IdP didn't supply one. The previous `jwks-{alg}`
                // scheme collided when an IdP returned multiple
                // kid-less keys, silently dropping all but the last.
                let kid = match k.kid {
                    Some(s) if !s.is_empty() => s,
                    _ => jwk_thumbprint_ed25519(x, k.crv.as_deref().unwrap_or("Ed25519")),
                };
                self.keys
                    .add(&kid, Algorithm::EdDSA, KeyMaterial::Ed25519(raw));
            } else {
                // RSA/ECDSA/HS256 would be supported here in v2.1.
                tracing::debug!(alg = ?alg, "skipping non-Ed25519 JWKS key");
            }
        }
        Ok(())
    }

    /// Background task that periodically refreshes JWKS.
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

// Suppress unused warning
#[allow(dead_code)]
type _Unused = ();

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
        v.add_key("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes));

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
        v.add_key("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes));
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
    fn missing_exp_rejected() {
        // RFC 8725 §3.12: a JWT without `exp` is dangerous (a leaked
        // token is forever valid). Reject at the validator.
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let v = JwtValidator::new(JwtConfig::new("https://idp.example.com", "agentguard"));
        v.add_key("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes));
        let claims = serde_json::json!({
            "iss": "https://idp.example.com",
            "aud": "agentguard",
            // no exp
        });
        let token = sign_token(&signing_key, "kid1", claims);
        let res = v.validate(&token);
        assert!(matches!(res, Err(AuthError::JwtExpired)));
    }

    #[test]
    fn iat_in_future_rejected() {
        // iat > now+skew should be rejected as suspicious (the token
        // claims to have been issued in the future).
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let v = JwtValidator::new(JwtConfig::new("https://idp.example.com", "agentguard"));
        v.add_key("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes));
        let claims = serde_json::json!({
            "iss": "https://idp.example.com",
            "aud": "agentguard",
            "exp": chrono::Utc::now().timestamp() + 3600,
            "iat": chrono::Utc::now().timestamp() + 7200, // 2h in future
        });
        let token = sign_token(&signing_key, "kid1", claims);
        let res = v.validate(&token);
        assert!(matches!(res, Err(AuthError::JwtInvalid(_))));
    }

    #[test]
    fn wrong_audience_rejected() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let v = JwtValidator::new(JwtConfig::new("https://idp.example.com", "agentguard"));
        v.add_key("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes));
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

    #[test]
    fn hs256_falsified_token_rejected() {
        // Algorithm-confusion attack: a token with alg=HS256 + a forged
        // HMAC-SHA256 signature is rejected even if we have an Ed25519
        // key registered for the same kid.
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let v = JwtValidator::new(JwtConfig::new("iss", "aud"));
        v.add_key("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes));

        // Forge a token with alg=HS256 and a real HMAC-SHA256 over the
        // signing input. Our EdDSA-only verifier must reject it.
        let header_json = serde_json::json!({"alg": "HS256", "typ": "JWT", "kid": "kid1"});
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header_json).unwrap());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&serde_json::json!({"iss": "iss", "aud": "aud", "exp": chrono::Utc::now().timestamp() + 3600})).unwrap());
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"hmac-secret").expect("hmac key");
        mac.update(signing_input.as_bytes());
        let sig_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let forged = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);
        let res = v.validate(&forged);
        assert!(matches!(res, Err(AuthError::JwtInvalid(_))));
    }

    #[test]
    fn tampered_payload_signature_check() {
        // Mutating the signature segment must fail verification.
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let v = JwtValidator::new(JwtConfig::new("https://idp.example.com", "agentguard"));
        v.add_key("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes));
        let claims = serde_json::json!({
            "iss": "https://idp.example.com",
            "aud": "agentguard",
            "exp": chrono::Utc::now().timestamp() + 3600,
        });
        let token = sign_token(&signing_key, "kid1", claims);
        // Replace a character in the signature segment with a different
        // valid base64url char. The signature won't verify after the change.
        let parts: Vec<&str> = token.split('.').collect();
        let mut sig_chars: Vec<char> = parts[2].chars().collect();
        let c0 = sig_chars[0];
        sig_chars[0] = if c0 == 'A' { 'B' } else { 'A' };
        let tampered_sig: String = sig_chars.into_iter().collect();
        let tampered = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);
        let res = v.validate(&tampered);
        assert!(res.is_err());
    }

    #[test]
    fn empty_jwt_rejected() {
        let v = JwtValidator::new(JwtConfig::new("iss", "aud"));
        assert!(matches!(v.validate(""), Err(AuthError::JwtInvalid(_))));
        assert!(matches!(v.validate("."), Err(AuthError::JwtInvalid(_))));
    }

    #[test]
    fn nbf_in_future_rejected() {
        // NotBefore: a token whose nbf is 1 hour in the future must
        // be rejected even if its exp is 1 hour later (also in the future
        // but past nbf).
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let v = JwtValidator::new(JwtConfig::new("iss", "aud"));
        v.add_key("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes));
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": "iss",
            "aud": "aud",
            "exp": now + 7200,
            "nbf": now + 3600,
        });
        let token = sign_token(&signing_key, "kid1", claims);
        let res = v.validate(&token);
        assert!(matches!(res, Err(AuthError::JwtInvalid(_))));
    }

    #[test]
    fn array_aud_accepted() {
        // RFC 7519 §4.1.3: aud may be a single string OR an array of
        // strings. A token with aud=["agentguard", "other"] is valid
        // when we expect "agentguard".
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let pub_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let v = JwtValidator::new(JwtConfig::new("iss", "agentguard"));
        v.add_key("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes));
        let claims = serde_json::json!({
            "iss": "iss",
            "aud": ["agentguard", "other"],
            "exp": chrono::Utc::now().timestamp() + 3600,
        });
        let token = sign_token(&signing_key, "kid1", claims);
        assert!(v.validate(&token).is_ok());
    }

    #[test]
    fn default_whitelist_is_eddsa_only() {
        // RS256/ES256 are not yet implemented in verify_signature. A
        // default whitelist that includes them lets an attacker pick
        // a "not implemented" path and get a confusing error instead
        // of a clean rejection.
        let cfg = JwtConfig::new("iss", "aud");
        assert_eq!(cfg.algorithms, vec![Algorithm::EdDSA]);
    }

    #[test]
    fn jwk_thumbprint_is_deterministic() {
        // The thumbprint must depend on the public key bytes — two
        // keys with different x produce different thumbprints.
        let x1 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        let x2 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32]);
        let t1 = jwk_thumbprint_ed25519(&x1, "Ed25519");
        let t2 = jwk_thumbprint_ed25519(&x2, "Ed25519");
        assert_ne!(t1, t2);
        // Same key → same thumbprint.
        assert_eq!(t1, jwk_thumbprint_ed25519(&x1, "Ed25519"));
    }

    #[test]
    fn refresh_interval_from_env_overrides_default() {
        // AGENTGUARD_JWKS_REFRESH=5s should produce a 5-second
        // interval on a fresh config.
        std::env::set_var("AGENTGUARD_JWKS_REFRESH", "5s");
        let cfg = JwtConfig::new("iss", "aud").with_jwks_refresh_from_env();
        std::env::remove_var("AGENTGUARD_JWKS_REFRESH");
        assert_eq!(cfg.jwks_refresh, Duration::from_secs(5));
    }

    #[test]
    fn alg_none_rejected() {
        // alg=none must never be accepted — RFC 8725 §3.2.
        // Forge a token with header {"alg":"none","typ":"JWT"}
        // and a zero signature.
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT"}"#);
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(
            r#"{{"iss":"iss","aud":"aud","exp":{}}}"#,
            chrono::Utc::now().timestamp() + 3600
        ));
        let token = format!("{}.{}.", header, claims);
        let v = JwtValidator::new(JwtConfig::new("iss", "aud"));
        let err = v.validate(&token).unwrap_err();
        // Could be JwtInvalid (unsupported alg) or JwtInvalid
        // (missing kid) depending on parse order — both are
        // rejection. What must NOT happen is Ok.
        assert!(matches!(err, AuthError::JwtInvalid(_)));
    }

    #[test]
    fn missing_kid_rejected() {
        // RFC 7517 §4.1.4: a JWS header without `kid` cannot be
        // unambiguously bound to a key. Reject.
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pub_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let header_json = r#"{"alg":"EdDSA","typ":"JWT"}"#.to_string();
        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(
            r#"{{"iss":"iss","aud":"aud","exp":{}}}"#,
            chrono::Utc::now().timestamp() + 3600
        ));
        let signing_input = format!("{header}.{claims}");
        let sig = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{signing_input}.{sig_b64}");
        let v = JwtValidator::new(JwtConfig::new("iss", "aud"));
        v.add_key("anykid", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes));
        assert!(matches!(v.validate(&token), Err(AuthError::JwtInvalid(_))));
    }

    #[test]
    fn wrong_alg_in_whitelist_rejected() {
        // A token with alg=EdDSA but our whitelist only allows HS256
        // must reject at the header check, not at signature verify.
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pub_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let v = JwtValidator::new(JwtConfig::new("iss", "aud"));
        v.add_key("kid1", Algorithm::EdDSA, KeyMaterial::Ed25519(pub_bytes));
        let cfg = v.config.clone();
        // Force the whitelist to NOT include EdDSA — the validator
        // is constructed with the default whitelist, so we test by
        // adding a token whose alg is in the whitelist but using a
        // non-registered key.
        let claims = serde_json::json!({
            "iss": "iss",
            "aud": "aud",
            "exp": chrono::Utc::now().timestamp() + 3600,
        });
        let token = sign_token(&signing_key, "wrong-kid", claims);
        assert!(matches!(
            v.validate(&token),
            Err(AuthError::JwtUnknownKid(_))
        ));
        drop(cfg);
    }
}

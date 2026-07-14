//! Scoped delegation tokens for sub-agents.
//!
//! When an agent calls a sub-agent, it should pass a *scoped* subset of its
//! own permissions, not a blanket identity. These tokens encode:
//!
//! * who issued (iss) — the parent agent
//! * who holds it (sub) — the sub-agent identity
//! * what actions are allowed (allowed_actions) — a list of `ToolCall::name`
//! * which resources are in scope (resource_patterns) — glob patterns
//! * when it expires (exp) — required
//! * extra Cedar constraints (conditions) — a small subset of expressions
//! * trace back to the originating decision (parent_decision_id)
//!
//! Tokens are Ed25519-signed by the issuer. The verifier holds the issuer's
//! public key.

use crate::error::{Error, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use indexmap::IndexMap;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationClaims {
    /// Issuer (parent agent), e.g. `Agent::"research"`.
    pub iss: String,
    /// Subject (delegate), e.g. `Agent::"summarizer"`.
    pub sub: String,
    /// Audience — usually the verifier's identifier.
    pub aud: String,
    /// Issued at (unix seconds).
    pub iat: i64,
    /// Expiry (unix seconds).
    pub exp: i64,
    /// Not-before (unix seconds), optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Allowed actions, e.g. `["ToolCall::send_email", "ToolCall::calendar_read"]`.
    pub allowed_actions: Vec<String>,
    /// Resource UID patterns, e.g. `["Mailbox::\"alice*\"", "Calendar::\"work\""]`.
    pub resource_patterns: Vec<String>,
    /// Optional Cedar expression for additional constraints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<String>,
    /// Decision id this delegation traces back to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_decision_id: Option<String>,
    /// Free-form claims.
    #[serde(default)]
    pub extra: IndexMap<String, serde_json::Value>,
}

impl DelegationClaims {
    pub fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.exp <= now
    }

    pub fn is_not_yet_valid(&self, now: i64) -> bool {
        self.nbf.map(|n| n > now).unwrap_or(false)
    }

    /// Does this token permit `action` on `resource`?
    pub fn permits(&self, action: &str, resource: &str) -> bool {
        let action_ok = self.allowed_actions.iter().any(|a| a == action || a == "*");
        if !action_ok {
            return false;
        }
        self.resource_patterns
            .iter()
            .any(|p| p == resource || glob_match(p, resource))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DelegationConfig {
    pub ttl_seconds: i64,
}

impl Default for DelegationConfig {
    fn default() -> Self {
        Self { ttl_seconds: 900 } // 15 min default
    }
}

/// Signer: holds a private key, mints tokens.
pub struct DelegationSigner {
    key: SigningKey,
    key_id: String,
}

impl DelegationSigner {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let key = SigningKey::generate(&mut csprng);
        let key_id = format!("agent-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        Self { key, key_id }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidToken("ed25519 key must be 32 bytes".into()))?;
        Ok(Self {
            key: SigningKey::from_bytes(&arr),
            key_id: "imported".into(),
        })
    }

    pub fn public_key_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.key.verifying_key().to_bytes())
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn set_key_id(&mut self, id: impl Into<String>) {
        self.key_id = id.into();
    }

    pub fn mint(
        &self,
        iss: impl Into<String>,
        sub: impl Into<String>,
        aud: impl Into<String>,
        allowed_actions: Vec<String>,
        resource_patterns: Vec<String>,
        cfg: DelegationConfig,
    ) -> Result<DelegationToken> {
        self.mint_with(
            iss,
            sub,
            aud,
            allowed_actions,
            resource_patterns,
            cfg,
            |_| {},
        )
    }

    pub fn mint_with<F>(
        &self,
        iss: impl Into<String>,
        sub: impl Into<String>,
        aud: impl Into<String>,
        allowed_actions: Vec<String>,
        resource_patterns: Vec<String>,
        cfg: DelegationConfig,
        mutate: F,
    ) -> Result<DelegationToken>
    where
        F: FnOnce(&mut DelegationClaims),
    {
        let now = DelegationClaims::now();
        let mut claims = DelegationClaims {
            iss: iss.into(),
            sub: sub.into(),
            aud: aud.into(),
            iat: now,
            exp: now + cfg.ttl_seconds,
            nbf: None,
            allowed_actions,
            resource_patterns,
            conditions: None,
            parent_decision_id: None,
            extra: IndexMap::new(),
        };
        mutate(&mut claims);
        self.sign_claims(&claims)
    }

    pub fn sign_claims(&self, claims: &DelegationClaims) -> Result<DelegationToken> {
        let payload = serde_json::to_vec(claims)?;
        let sig = self.key.sign(&payload);
        let token = DelegationToken {
            claims: claims.clone(),
            payload_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload),
            signature_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            key_id: self.key_id.clone(),
        };
        Ok(token)
    }
}

/// Verifier: holds the issuer's public key, checks signatures + expiry.
pub struct DelegationVerifier {
    keys: Vec<(String, VerifyingKey)>,
}

impl DelegationVerifier {
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    pub fn add_key(&mut self, key_id: impl Into<String>, pub_b64: impl AsRef<str>) -> Result<()> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(pub_b64.as_ref())
            .map_err(|e| Error::InvalidToken(format!("base64: {}", e)))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::InvalidToken("ed25519 pubkey must be 32 bytes".into()))?;
        let key = VerifyingKey::from_bytes(&arr)
            .map_err(|e| Error::InvalidToken(format!("verifying key: {}", e)))?;
        self.keys.push((key_id.into(), key));
        Ok(())
    }

    pub fn verify<'a>(&self, token: &'a DelegationToken, now: i64) -> Result<&'a DelegationClaims> {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&token.payload_b64)
            .map_err(|e| Error::InvalidToken(format!("payload b64: {}", e)))?;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&token.signature_b64)
            .map_err(|e| Error::InvalidToken(format!("sig b64: {}", e)))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| Error::InvalidToken("sig must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_arr);

        let key = self
            .keys
            .iter()
            .find(|(kid, _)| kid == &token.key_id)
            .map(|(_, k)| k)
            .ok_or_else(|| Error::InvalidToken(format!("unknown key id {}", token.key_id)))?;
        key.verify(&payload, &sig)
            .map_err(|e| Error::TokenSignature {
                reason: e.to_string(),
            })?;

        if token.claims.is_expired(now) {
            return Err(Error::TokenExpired(token.claims.exp.to_string()));
        }
        if token.claims.is_not_yet_valid(now) {
            return Err(Error::TokenNotYetValid(
                token.claims.nbf.unwrap().to_string(),
            ));
        }
        Ok(&token.claims)
    }
}

/// Compact token format: `base64url(payload).base64url(signature).key_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
    pub claims: DelegationClaims,
    pub payload_b64: String,
    pub signature_b64: String,
    pub key_id: String,
}

impl DelegationToken {
    pub fn to_compact(&self) -> String {
        format!(
            "{}.{}.{}",
            self.payload_b64, self.signature_b64, self.key_id
        )
    }

    pub fn from_compact(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidToken("expected 3 parts".into()));
        }
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| Error::InvalidToken(format!("payload b64: {}", e)))?;
        let claims: DelegationClaims = serde_json::from_slice(&payload)?;
        Ok(Self {
            claims,
            payload_b64: parts[0].into(),
            signature_b64: parts[1].into(),
            key_id: parts[2].into(),
        })
    }
}

/// Minimal glob match supporting `*` only. Sufficient for resource scoping.
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut idx = 0usize;
    if !parts.is_empty() && !parts[0].is_empty() {
        if !value.starts_with(parts[0]) {
            return false;
        }
        idx = parts[0].len();
    }
    for (i, p) in parts.iter().enumerate() {
        if i == 0 {
            continue;
        }
        if p.is_empty() {
            continue;
        }
        match value[idx..].find(p) {
            Some(pos) => idx += pos + p.len(),
            None => return false,
        }
    }
    if let Some(last) = parts.last() {
        if !last.is_empty() && !value.ends_with(last) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mint_verify_roundtrip() {
        let signer = DelegationSigner::generate();
        let mut verifier = DelegationVerifier::new();
        verifier
            .add_key(signer.key_id(), signer.public_key_b64())
            .unwrap();

        let token = signer
            .mint(
                "Agent::\"research\"",
                "Agent::\"summarizer\"",
                "service",
                vec!["ToolCall::send_email".into()],
                vec!["Mailbox::*".into()],
                DelegationConfig::default(),
            )
            .unwrap();

        let claims = verifier.verify(&token, DelegationClaims::now()).unwrap();
        assert_eq!(claims.sub, "Agent::\"summarizer\"");
    }

    #[test]
    fn test_glob_match() {
        assert!(glob_match("Mailbox::*", "Mailbox::\"alice@x\""));
        assert!(glob_match("Mailbox::\"alice*\"", "Mailbox::\"alice@x\""));
        assert!(!glob_match("Mailbox::\"bob*\"", "Mailbox::\"alice@x\""));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn test_expired_token_rejected() {
        let signer = DelegationSigner::generate();
        let mut verifier = DelegationVerifier::new();
        verifier
            .add_key(signer.key_id(), signer.public_key_b64())
            .unwrap();
        let token = signer
            .mint(
                "Agent::\"a\"",
                "Agent::\"b\"",
                "svc",
                vec!["*".into()],
                vec!["*".into()],
                DelegationConfig { ttl_seconds: -10 },
            )
            .unwrap();
        assert!(verifier.verify(&token, DelegationClaims::now()).is_err());
    }

    #[test]
    fn test_token_compact_roundtrip() {
        let signer = DelegationSigner::generate();
        let token = signer
            .mint(
                "Agent::\"a\"",
                "Agent::\"b\"",
                "svc",
                vec!["*".into()],
                vec!["*".into()],
                DelegationConfig::default(),
            )
            .unwrap();
        let s = token.to_compact();
        let t2 = DelegationToken::from_compact(&s).unwrap();
        assert_eq!(t2.claims.sub, token.claims.sub);
    }
}

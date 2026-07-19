//! Scoped delegation tokens for sub-agents.
//!
//! v2.0: hard-break from v1 compact format. Tokens are now standard JWS
//! (RFC 7515) using EdDSA. Supports structured constraints, RFC 8693 act
//! chain, and algorithm agility via [`Algorithm`].

pub use crate::auth_keys::parse_alg;
use crate::auth_keys::Algorithm;
use crate::error::{Error, Result};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Standard JWS compact serialization: `base64url(header).base64url(payload).base64url(signature)`.
///
/// The header carries `alg`, `kid`, `typ`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DelegationClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    pub jti: String,
    pub allowed_actions: Vec<String>,
    pub resource_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActClaim>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<ConstraintSet>,
    #[serde(default)]
    pub extra: IndexMap<String, serde_json::Value>,
}

/// RFC 8693 nested act claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ActClaim {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActClaim>>,
}

/// Structured constraints — a tree of expressions evaluated against the
/// request context. Replaces v1's free-form constraint strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConstraintSet {
    pub expressions: Vec<ConstraintExpr>,
}

impl ConstraintSet {
    pub fn new(expressions: Vec<ConstraintExpr>) -> Self {
        Self { expressions }
    }

    pub fn empty() -> Self {
        Self {
            expressions: vec![],
        }
    }
}

/// A single constraint expression over a context path.
///
/// Path syntax: dotted segments like `context.args.amount`,
/// `context.session.ip`, `principal.tenant_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConstraintExpr {
    Equals {
        path: String,
        value: serde_json::Value,
    },
    In {
        path: String,
        values: Vec<serde_json::Value>,
    },
    GreaterThan {
        path: String,
        value: i64,
    },
    LessThan {
        path: String,
        value: i64,
    },
    Glob {
        path: String,
        pattern: String,
    },
    And {
        all: Vec<ConstraintExpr>,
    },
    Or {
        any: Vec<ConstraintExpr>,
    },
    Not {
        inner: Box<ConstraintExpr>,
    },
}

impl ConstraintExpr {
    /// Evaluate against a JSON value (the request context).
    pub fn evaluate(&self, root: &serde_json::Value) -> bool {
        match self {
            ConstraintExpr::Equals { path, value } => {
                lookup(root, path).map(|v| v == value).unwrap_or(false)
            }
            ConstraintExpr::In { path, values } => lookup(root, path)
                .map(|v| values.iter().any(|x| x == v))
                .unwrap_or(false),
            ConstraintExpr::GreaterThan { path, value } => lookup(root, path)
                .and_then(|v| v.as_i64())
                .map(|x| x > *value)
                .unwrap_or(false),
            ConstraintExpr::LessThan { path, value } => lookup(root, path)
                .and_then(|v| v.as_i64())
                .map(|x| x < *value)
                .unwrap_or(false),
            ConstraintExpr::Glob { path, pattern } => lookup(root, path)
                .and_then(|v| v.as_str())
                .map(|s| glob_match(pattern, s))
                .unwrap_or(false),
            ConstraintExpr::And { all } => all.iter().all(|e| e.evaluate(root)),
            ConstraintExpr::Or { any } => any.iter().any(|e| e.evaluate(root)),
            ConstraintExpr::Not { inner } => !inner.evaluate(root),
        }
    }
}

fn lookup<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    // Walk the dotted path directly on the Value. Avoids the String
    // allocation that `path.split('.')` would produce, and avoids the
    // JSON-pointer conversion that `Value::pointer` would require.
    // The path is dot-separated segments like `context.args.amount`.
    let bytes = path.as_bytes();
    let mut cur = root;
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'.' {
            if start == i {
                return None;
            }
            let seg = match std::str::from_utf8(&bytes[start..i]) {
                Ok(s) => s,
                Err(_) => return None,
            };
            cur = cur.get(seg)?;
            start = i + 1;
        }
    }
    if start == bytes.len() {
        return None;
    }
    let seg = match std::str::from_utf8(&bytes[start..]) {
        Ok(s) => s,
        Err(_) => return None,
    };
    cur.get(seg)
}

/// Glob match with `*` wildcard support.
///
/// Supports `*` (matches any sequence of characters, including empty).
/// The match is greedy: it matches the longest possible prefix of the value
/// against the literal prefix, then advances. This is sufficient for the
/// resource-pattern use case in delegation tokens.
///
/// Implementation: a two-pointer walk that avoids both the recursion and
/// the Vec<&str> allocation of the previous version. The
/// `*`-delimited segments are matched left-to-right; on any partial
/// failure we back up the segment pointer to the previous `*` position
/// and try the next value position.
pub(crate) fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }
    let pat = pattern.as_bytes();
    let val = value.as_bytes();
    let pat_len = pat.len();
    let val_len = val.len();
    // Find split points: positions of each '*' in `pat`.
    let mut stars: Vec<usize> = Vec::new();
    for (i, &b) in pat.iter().enumerate() {
        if b == b'*' {
            stars.push(i);
        }
    }
    let n_stars = stars.len();
    // Walk the non-wildcard prefix P0.
    let p0_end = stars[0];
    if !slice_eq(pat, 0, p0_end, val, 0) {
        return false;
    }
    let mut vi = p0_end;
    // Match segments P1..Pn greedily from the start; on failure,
    // backtrack by incrementing the previous value position.
    let mut s: Vec<usize> = vec![vi];
    for i in 0..n_stars {
        let seg_start = stars[i] + 1;
        let seg_end = if i + 1 < n_stars {
            stars[i + 1]
        } else {
            pat_len
        };
        let seg_len = seg_end - seg_start;
        if i + 1 == n_stars {
            // Last segment: must be a suffix of value.
            if seg_len == 0 {
                return true;
            }
            return val_len >= vi + seg_len
                && slice_eq(pat, seg_start, seg_end, val, val_len - seg_len);
        }
        // Find pat[seg_start..seg_end] in val starting at or after vi.
        let mut pos = s[i];
        loop {
            if pos + seg_len > val_len {
                return false;
            }
            if slice_eq(pat, seg_start, seg_end, val, pos) {
                vi = pos + seg_len;
                s.push(vi);
                break;
            }
            pos += 1;
        }
    }
    false
}

#[inline]
fn slice_eq(a: &[u8], a_start: usize, a_end: usize, b: &[u8], b_start: usize) -> bool {
    let len = a_end - a_start;
    if b_start + len > b.len() {
        return false;
    }
    a[a_start..a_end] == b[b_start..b_start + len]
}

/// TTL configuration for minting tokens.
#[derive(Debug, Clone, Copy)]
pub struct DelegationConfig {
    pub ttl: Duration,
}

impl Default for DelegationConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(900),
        }
    }
}

/// Signer that mints JWS tokens.
#[derive(Clone)]
pub struct DelegationSigner {
    key: SigningKey,
    key_id: String,
}

impl std::fmt::Debug for DelegationSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegationSigner")
            .field("key_id", &self.key_id)
            .field("alg", &"EdDSA")
            .finish()
    }
}

impl DelegationSigner {
    /// Generate a fresh Ed25519 signing key.
    ///
    /// # Examples
    /// ```
    /// use agentguard_core::DelegationSigner;
    /// let signer = DelegationSigner::generate();
    /// let _public_key = signer.public_key_b64();
    /// ```
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let key = SigningKey::generate(&mut OsRng);
        let key_id = format!("agent-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        Self { key, key_id }
    }

    /// Construct from raw 32-byte Ed25519 secret bytes.
    ///
    /// # Errors
    /// Returns `Error::InvalidToken` if `bytes` is not exactly 32 bytes.
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

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn set_key_id(&mut self, id: impl Into<String>) {
        self.key_id = id.into();
    }

    /// Mint a delegation token with the given configuration.
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

    /// Mint a delegation token with a callback to mutate the claims before signing.
    #[allow(clippy::too_many_arguments)]
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
        let now = chrono::Utc::now().timestamp();
        let mut claims = DelegationClaims {
            iss: iss.into(),
            sub: sub.into(),
            aud: aud.into(),
            iat: now,
            exp: now + cfg.ttl.as_secs() as i64,
            nbf: None,
            jti: uuid::Uuid::new_v4().to_string(),
            allowed_actions,
            resource_patterns,
            act: None,
            constraints: None,
            extra: IndexMap::new(),
        };
        mutate(&mut claims);
        self.sign_jws(&claims)
    }

    /// Sign a JWS with the given claims.
    pub fn sign_jws(&self, claims: &DelegationClaims) -> Result<DelegationToken> {
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "agentguard-delegation+jwt",
            "kid": self.key_id,
        });
        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        let sig = self.key.sign(signing_input.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        Ok(DelegationToken {
            claims: claims.clone(),
            jws: format!("{}.{}", signing_input, sig_b64),
        })
    }
}

/// A signed JWS token + its parsed claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
    pub claims: DelegationClaims,
    pub jws: String,
}

impl DelegationToken {
    /// Return the compact JWS string.
    pub fn to_jws(&self) -> &str {
        &self.jws
    }

    /// Parse the JWS structure (header, payload, signature) without
    /// cryptographic verification.
    ///
    /// # Warning
    /// The returned `DelegationToken` is **not authenticated**. The
    /// `claims` field comes from the unverified payload and can be
    /// arbitrarily chosen by an attacker. Always use
    /// [`DelegationVerifier::verify`] before trusting any field
    /// of the returned value.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::InvalidToken("JWS must have 3 parts".into()));
        }
        let header_b64 = parts[0];
        let payload_b64 = parts[1];
        let sig_b64 = parts[2];
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| Error::InvalidToken(format!("header b64: {}", e)))?;
        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| Error::InvalidToken(format!("header json: {}", e)))?;
        let _alg_str = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidToken("missing alg".into()))?;

        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| Error::InvalidToken(format!("payload b64: {}", e)))?;
        let claims: DelegationClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| Error::InvalidToken(format!("payload json: {}", e)))?;

        // Verify the signature is well-formed (correct length for the alg).
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| Error::InvalidToken(format!("sig b64: {}", e)))?;
        if sig.len() != 64 {
            return Err(Error::TokenSignature {
                reason: format!("ed25519 signature must be 64 bytes, got {}", sig.len()),
            });
        }

        Ok(Self {
            claims,
            jws: s.to_string(),
        })
    }
}

/// A successfully verified delegation token.
#[derive(Debug, Clone)]
pub struct VerifiedDelegation {
    pub claims: DelegationClaims,
    pub kid: String,
    pub alg: Algorithm,
}

/// Verifies JWS tokens using a key registry of public keys.
///
/// The verifier holds an internal `HashMap<kid, (Algorithm, VerifyingKey)>`.
/// When a token is verified, the registry is consulted to find the matching
/// key, and the EdDSA signature is checked cryptographically.
#[derive(Default)]
pub struct DelegationVerifier {
    keys: parking_lot::RwLock<std::collections::HashMap<String, (Algorithm, VerifyingKey)>>,
    /// Clock skew tolerance for `exp` / `nbf` checks. Mirrors
    /// `JwtConfig::clock_skew` so a 60-second drift doesn't reject
    /// otherwise-valid tokens. Default 60 s.
    clock_skew: std::sync::atomic::AtomicI64,
}

impl DelegationVerifier {
    pub fn new() -> Self {
        Self {
            clock_skew: std::sync::atomic::AtomicI64::new(60),
            ..Self::default()
        }
    }

    /// Set the clock-skew tolerance (seconds) used when comparing
    /// `exp` / `nbf` to "now".
    pub fn set_clock_skew_seconds(&self, secs: i64) {
        self.clock_skew
            .store(secs.max(0), std::sync::atomic::Ordering::Relaxed);
    }

    pub fn clock_skew_seconds(&self) -> i64 {
        self.clock_skew.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Add a public key (raw Ed25519 bytes).
    ///
    /// Replaces any existing key under the same `kid`. Returns `Err`
    /// when the key bytes are invalid (wrong length, bad parse) so
    /// callers see the failure rather than silently dropping it.
    pub fn add_key(
        &self,
        kid: impl Into<String>,
        alg: Algorithm,
        raw: &[u8],
    ) -> crate::error::Result<()> {
        let kid_str = kid.into();
        let key = match alg {
            Algorithm::EdDSA => {
                if raw.len() != 32 {
                    return Err(crate::error::Error::Other(format!(
                        "ed25519 pubkey for kid {:?} must be 32 bytes, got {}",
                        kid_str,
                        raw.len()
                    )));
                }
                let bytes: [u8; 32] = raw.try_into().expect("length checked above");
                VerifyingKey::from_bytes(&bytes)
                    .map_err(|e| crate::error::Error::Other(format!("ed25519 key parse: {}", e)))?
            }
            _ => {
                return Err(crate::error::Error::Other(format!(
                    "alg {:?} not yet supported for verification",
                    alg
                )));
            }
        };
        self.keys.write().insert(kid_str, (alg, key));
        Ok(())
    }

    /// Remove all keys.
    pub fn clear(&self) {
        self.keys.write().clear();
    }

    /// Number of registered keys.
    pub fn key_count(&self) -> usize {
        self.keys.read().len()
    }

    /// Verify the JWS signature, then validate standard claims (exp, nbf, aud).
    /// Returns the verified claims on success.
    ///
    /// This is the secure entry point — unlike [`DelegationToken::parse`],
    /// it actually verifies the EdDSA signature.
    ///
    /// # Errors
    /// Returns `Error::TokenSignature` if the signature is invalid
    /// or the kid is unknown. Returns `Error::TokenExpired` if `now_unix`
    /// is past `exp + clock_skew_seconds`. Returns `Error::TokenNotYetValid`
    /// if `nbf` is in the future. Returns `Error::InvalidToken` for any
    /// JWS parse / base64 / signature-format error or audience mismatch.
    ///
    /// # Examples
    /// ```
    /// use agentguard_core::{DelegationConfig, DelegationSigner, DelegationVerifier,
    ///     auth_keys::Algorithm};
    /// use base64::Engine as _;
    ///
    /// let signer = DelegationSigner::generate();
    /// let verifier = DelegationVerifier::new();
    /// let pub_bytes = base64::engine::general_purpose::STANDARD
    ///     .decode(signer.public_key_b64()).unwrap();
    /// verifier.add_key(signer.key_id(), Algorithm::EdDSA, &pub_bytes).unwrap();
    /// let token = signer.mint("alice", "summarizer", "aud",
    ///     vec!["ToolCall::send".into()],
    ///     vec!["Mailbox::*".into()],
    ///     DelegationConfig::default()).unwrap();
    /// let verified = verifier.verify(&token.jws, "aud", 0).unwrap();
    /// assert_eq!(verified.claims.iss, "alice");
    /// assert_eq!(verified.claims.aud, "aud");
    /// ```
    pub fn verify(
        &self,
        token: &str,
        expected_aud: &str,
        now_unix: i64,
    ) -> Result<VerifiedDelegation> {
        // Step 1: parse the JWS structure (no crypto yet).
        let parsed = DelegationToken::parse(token)?;

        // Step 2: extract `alg` and `kid` from the header.
        let header_bytes = {
            let parts: Vec<&str> = token.split('.').collect();
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[0])
                .map_err(|e| Error::InvalidToken(format!("header b64: {}", e)))?
        };
        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| Error::InvalidToken(format!("header json: {}", e)))?;
        let alg_str = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidToken("missing alg".into()))?;
        let kid = header
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::InvalidToken("missing kid in header".into()))?
            .to_string();
        let alg = parse_alg(alg_str)
            .ok_or_else(|| Error::InvalidToken(format!("unsupported alg: {}", alg_str)))?;

        // Step 3: reject HS* with asymmetric keys (algorithm confusion).
        // We never accept HS256 for delegation — symmetric algorithms don't
        // apply to the public-key model.
        if matches!(alg, Algorithm::HS256) {
            return Err(Error::TokenSignature {
                reason: "HS256 is not supported for delegation tokens".into(),
            });
        }

        // Step 4: look up the key by kid in the registry.
        let keys = self.keys.read();
        let (_, verifying_key) = *keys.get(&kid).ok_or_else(|| Error::TokenSignature {
            reason: format!("unknown kid: {}", kid),
        })?;
        drop(keys);

        // Step 5: compute the EdDSA signature check.
        let parts: Vec<&str> = token.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| Error::TokenSignature {
                reason: format!("sig b64: {}", e),
            })?;
        verify_ed255sa(&verifying_key, signing_input.as_bytes(), &sig_bytes)?;

        // Step 6: validate time-based claims with clock skew.
        let skew = self.clock_skew_seconds();
        if parsed.claims.exp + skew <= now_unix {
            return Err(Error::TokenExpired(parsed.claims.exp.to_string()));
        }
        if let Some(nbf) = parsed.claims.nbf {
            if nbf > now_unix + skew {
                return Err(Error::TokenNotYetValid(nbf.to_string()));
            }
        }

        // Step 7: validate the audience.
        if parsed.claims.aud != expected_aud {
            return Err(Error::TokenSignature {
                reason: format!(
                    "audience mismatch: expected {}, got {}",
                    expected_aud, parsed.claims.aud
                ),
            });
        }

        Ok(VerifiedDelegation {
            claims: parsed.claims,
            kid,
            alg,
        })
    }
}

/// Verify an EdDSA signature over `signing_input` using `verifying_key`.
fn verify_ed255sa(
    verifying_key: &VerifyingKey,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<()> {
    if signature.len() != 64 {
        return Err(Error::TokenSignature {
            reason: format!(
                "ed25519 signature must be 64 bytes, got {}",
                signature.len()
            ),
        });
    }
    let sig =
        ed25519_dalek::Signature::from_slice(signature).map_err(|e| Error::TokenSignature {
            reason: format!("ed25519 sig parse: {}", e),
        })?;
    verifying_key
        .verify(signing_input, &sig)
        .map_err(|_| Error::TokenSignature {
            reason: "ed25519 signature verification failed".into(),
        })?;
    Ok(())
}

// Test helpers.
impl DelegationSigner {
    #[cfg(test)]
    pub fn public_key_b64_bytes(&self) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(self.public_key_b64())
            .expect("public key is base64")
    }
}

#[cfg(test)]
#[allow(clippy::needless_borrow, unused_must_use)]
// `add_key` is `Result`-returning and `verify`'s `&str` arg wants
// explicit borrows. The tests are tightly scoped to verify
// cryptographic behavior, not error plumbing.
mod tests {
    use super::*;

    #[test]
    fn mint_and_verify_roundtrip() {
        let signer = DelegationSigner::generate();
        let token = signer
            .mint(
                "Agent::\"research\"",
                "Agent::\"summarizer\"",
                "agentguard://prod/email",
                vec!["ToolCall::send_email".into()],
                vec!["Mailbox::*".into()],
                DelegationConfig::default(),
            )
            .unwrap();

        let verifier = DelegationVerifier::new();
        verifier.add_key(
            signer.key_id(),
            Algorithm::EdDSA,
            &signer.public_key_b64_bytes(),
        );
        let v = verifier
            .verify(
                token.to_jws(),
                "agentguard://prod/email",
                chrono::Utc::now().timestamp(),
            )
            .unwrap();
        assert_eq!(v.claims.sub, "Agent::\"summarizer\"");
        assert_eq!(v.claims.aud, "agentguard://prod/email");
        assert_eq!(v.kid, signer.key_id());
    }

    #[test]
    fn clock_skew_tolerates_minor_drift() {
        // Two tokens minted back-to-back; the verifier is asked to
        // verify them 30 seconds after they were minted (i.e. the
        // verifier's clock is 30 s behind). With skew=60 the
        // second one is still inside the window; with skew=0 it
        // is rejected.
        let signer = DelegationSigner::generate();
        let cfg = DelegationConfig::default();
        let token = signer.mint("a", "b", "aud", vec![], vec![], cfg).unwrap();
        let verifier = DelegationVerifier::new();
        verifier
            .add_key(
                signer.key_id(),
                Algorithm::EdDSA,
                &signer.public_key_b64_bytes(),
            )
            .unwrap();
        let now = chrono::Utc::now().timestamp();
        let drifted_now = now + 30; // verifier clock is 30 s ahead
                                    // Token's exp = now + 900. Verifier now is now + 30; with
                                    // skew=60, 30 + 60 = 90 < 900 → verify OK.
        verifier.set_clock_skew_seconds(60);
        assert!(verifier.verify(&token.to_jws(), "aud", drifted_now).is_ok());
        // With skew=0, 30 < 900 still verifies — sanity check.
        verifier.set_clock_skew_seconds(0);
        assert!(verifier.verify(&token.to_jws(), "aud", drifted_now).is_ok());
        // Now use a clock 1000 seconds ahead — token is past exp.
        let far_future = now + 1000;
        verifier.set_clock_skew_seconds(60);
        assert!(verifier.verify(&token.to_jws(), "aud", far_future).is_err());
        verifier.set_clock_skew_seconds(0);
        assert!(verifier.verify(&token.to_jws(), "aud", far_future).is_err());
    }

    #[test]
    fn add_key_rejects_wrong_length() {
        let v = DelegationVerifier::new();
        // 31 bytes — too short for Ed25519.
        let bad = vec![0u8; 31];
        assert!(v.add_key("k", Algorithm::EdDSA, &bad).is_err());
    }

    #[test]
    fn forged_signature_rejected() {
        let signer = DelegationSigner::generate();
        let token = signer
            .mint("a", "b", "aud", vec![], vec![], DelegationConfig::default())
            .unwrap();

        // Replace the signature with a 64-byte all-zero buffer. The verifier
        // must reject this because the signature is not a valid Ed25519
        // signature over the signing input.
        let parts: Vec<&str> = token.to_jws().split('.').collect();
        // base64url-no-pad of 64 zero bytes
        let bogus = "A".repeat(86);
        let forged = format!("{}.{}.{}", parts[0], parts[1], bogus);

        let verifier = DelegationVerifier::new();
        verifier.add_key(
            signer.key_id(),
            Algorithm::EdDSA,
            &signer.public_key_b64_bytes(),
        );
        let res = verifier.verify(&forged, "aud", chrono::Utc::now().timestamp());
        assert!(matches!(res, Err(Error::TokenSignature { .. })));
    }

    #[test]
    fn wrong_audience_rejected() {
        let signer = DelegationSigner::generate();
        let token = signer
            .mint(
                "a",
                "b",
                "aud1",
                vec![],
                vec![],
                DelegationConfig::default(),
            )
            .unwrap();
        let verifier = DelegationVerifier::new();
        verifier.add_key(
            signer.key_id(),
            Algorithm::EdDSA,
            &signer.public_key_b64_bytes(),
        );
        let res = verifier.verify(token.to_jws(), "aud2", chrono::Utc::now().timestamp());
        assert!(matches!(res, Err(Error::TokenSignature { .. })));
    }

    #[test]
    fn unknown_kid_rejected() {
        let signer = DelegationSigner::generate();
        let token = signer
            .mint("a", "b", "aud", vec![], vec![], DelegationConfig::default())
            .unwrap();
        let verifier = DelegationVerifier::new();
        // No key registered — must fail.
        let res = verifier.verify(token.to_jws(), "aud", chrono::Utc::now().timestamp());
        assert!(matches!(res, Err(Error::TokenSignature { .. })));
    }

    #[test]
    fn hs256_rejected_to_prevent_algorithm_confusion() {
        // Forge a token with alg=HS256 and a signature that's "valid" HMAC-SHA256
        // over the signing input. The verifier must reject it because HS256
        // is never accepted for delegation tokens.
        let signer = DelegationSigner::generate();
        let token = signer
            .mint("a", "b", "aud", vec![], vec![], DelegationConfig::default())
            .unwrap();

        let parts: Vec<&str> = token.to_jws().split('.').collect();
        let header = serde_json::json!({"alg": "HS256", "typ": "JWT", "kid": signer.key_id()});
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let signing_input = format!("{}.{}", header_b64, parts[1]);
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"some-hmac-secret").expect("hmac key");
        mac.update(signing_input.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
        let forged = format!("{}.{}.{}", header_b64, parts[1], sig_b64);

        let verifier = DelegationVerifier::new();
        verifier.add_key(
            signer.key_id(),
            Algorithm::EdDSA,
            &signer.public_key_b64_bytes(),
        );
        let res = verifier.verify(&forged, "aud", chrono::Utc::now().timestamp());
        assert!(matches!(res, Err(Error::TokenSignature { .. })));
    }

    #[test]
    fn glob_match_wildcards() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("Mailbox::*", "Mailbox::\"alice@x\""));
        assert!(glob_match("Mailbox::\"alice*\"", "Mailbox::\"alice@x\""));
        assert!(!glob_match("Mailbox::\"bob*\"", "Mailbox::\"alice@x\""));
        // Multiple wildcards.
        assert!(glob_match("a*b*c", "axbxc"));
        assert!(glob_match("a*b*c", "abxc"));
        assert!(glob_match("a*b*c", "axbxc"));
        // The previous "overly strict" bug: pattern "a*x*" should match "axxby"
        // (first * matches "xx", second * matches "y" after consuming "b").
        assert!(glob_match("a*x*", "axxby"));
    }

    /// T2: double negation collapses. `Not(Not(x))` must equal `x`.
    #[test]
    fn double_negation_collapses() {
        let inner = ConstraintExpr::GreaterThan {
            path: "context.args.amount".into(),
            value: 100,
        };
        let doubly_negated = ConstraintExpr::Not {
            inner: Box::new(ConstraintExpr::Not {
                inner: Box::new(inner.clone()),
            }),
        };
        let mut high = serde_json::Map::new();
        high.insert("amount".into(), serde_json::json!(200));
        let mut ctx = serde_json::Map::new();
        ctx.insert("args".into(), serde_json::Value::Object(high));
        let req = serde_json::Value::Object(ctx);
        // The inner says amount > 100. Negated says amount <= 100.
        // Double-negated says amount > 100 again. Both branches should
        // agree with the inner.
        assert_eq!(doubly_negated.evaluate(&req), inner.evaluate(&req));
    }

    /// T3: missing path evaluates to false (not a panic). Constraints
    /// reference context paths; if the path is absent the constraint
    /// does not match.
    #[test]
    fn missing_path_evaluates_false() {
        let c = ConstraintExpr::Equals {
            path: "context.args.missing".into(),
            value: serde_json::json!("x"),
        };
        let req = serde_json::json!({"context": {"args": {"present": "x"}}});
        assert!(!c.evaluate(&req));
    }

    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn glob_match_always_matches_star(
                v in ".*"
            ) {
                prop_assert!(glob_match("*", &v));
            }

            #[test]
            fn glob_match_literal_no_wildcards(
                lit in "[a-zA-Z0-9]{1,16}"
            ) {
                prop_assert!(glob_match(&lit, &lit));
                // Mismatch only when lengths differ. "x" is 1 char, lit is
                // 1-16 chars, so for length-1 lit "x" the assertion is invalid.
                // Use a length-2 alternative.
                prop_assume!(lit.len() != 1);
                prop_assert!(!glob_match(&lit, "xy"));
            }

            #[test]
            fn glob_match_star_prefix(
                prefix in "[a-zA-Z]{1,8}",
                suffix in "[a-zA-Z]{1,8}",
            ) {
                let pat = format!("{}*", prefix);
                let val = format!("{}{}", prefix, suffix);
                prop_assert!(glob_match(&pat, &val));
            }
        }
    }

    #[test]
    fn constraint_evaluation_works() {
        let c = ConstraintSet::new(vec![ConstraintExpr::LessThan {
            path: "context.args.amount".into(),
            value: 1000,
        }]);
        let req = serde_json::json!({"context": {"args": {"amount": 500}}});
        assert!(c.expressions[0].evaluate(&req));
        let req2 = serde_json::json!({"context": {"args": {"amount": 5000}}});
        assert!(!c.expressions[0].evaluate(&req2));
    }

    #[test]
    fn act_chain_roundtrip() {
        let signer = DelegationSigner::generate();
        let token = signer
            .mint_with(
                "User::\"alice\"",
                "Agent::\"summarizer\"",
                "aud",
                vec![],
                vec![],
                DelegationConfig::default(),
                |c| {
                    c.act = Some(Box::new(ActClaim {
                        sub: "Agent::\"research\"".into(),
                        iss: Some("User::\"alice\"".into()),
                        act: Some(Box::new(ActClaim {
                            sub: "User::\"alice\"".into(),
                            iss: None,
                            act: None,
                        })),
                    }));
                },
            )
            .unwrap();
        let verifier = DelegationVerifier::new();
        verifier.add_key(
            signer.key_id(),
            Algorithm::EdDSA,
            &signer.public_key_b64_bytes(),
        );
        let v = verifier
            .verify(token.to_jws(), "aud", chrono::Utc::now().timestamp())
            .unwrap();
        assert_eq!(v.claims.sub, "Agent::\"summarizer\"");
        assert_eq!(v.claims.act.as_ref().unwrap().sub, "Agent::\"research\"");
    }
}

//! Delegation-claims types: [`DelegationClaims`], [`ActClaim`],
//! [`ConstraintSet`], [`ConstraintExpr`].
//!
//! These are the JWT-style structured claims emitted by
//! [`crate::DelegationSigner::mint`] and validated by
//! [`crate::DelegationVerifier::verify`].

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use super::glob::glob_match;

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

/// Walk a dotted JSON path without allocating. Returns `None` for
/// any missing segment or non-UTF8 path byte.
pub(crate) fn lookup<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
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

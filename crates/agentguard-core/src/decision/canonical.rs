//! Canonical JSON serialization (simplified RFC 8785).
//!
//! We don't implement the full RFC 8785 (which covers numeric edge cases);
//! instead we sort object keys deterministically and emit the same shape as
//! `serde_json::to_vec`. This is sufficient for hash-chain inputs where the
//! producer and verifier are both Rust processes.

use crate::error::Result;
use serde::Serialize;
use serde_json::{Map, Value};

/// Serialize `value` as canonical JSON: object keys sorted lexicographically.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let v = serde_json::to_value(value)?;
    Ok(canonical_value_bytes(&v))
}

fn canonical_value_bytes(v: &Value) -> Vec<u8> {
    match v {
        Value::Null => b"null".to_vec(),
        Value::Bool(b) => b.to_string().into_bytes(),
        Value::Number(n) => n.to_string().into_bytes(),
        Value::String(s) => serde_json::to_vec(s).unwrap_or_default(),
        Value::Array(arr) => {
            let mut out = vec![b'['];
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend(canonical_value_bytes(item));
            }
            out.push(b']');
            out
        }
        Value::Object(obj) => canonical_object_bytes(obj),
    }
}

fn canonical_object_bytes(obj: &Map<String, Value>) -> Vec<u8> {
    // Sort keys lexicographically.
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();

    let mut out = vec![b'{'];
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        // Serialize the key as a JSON string.
        let key_bytes = serde_json::to_vec(k).unwrap_or_default();
        out.extend(key_bytes);
        out.push(b':');
        out.extend(canonical_value_bytes(&obj[*k]));
    }
    out.push(b'}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_object_canonical() {
        let v = json!({});
        assert_eq!(canonical_value_bytes(&v), b"{}");
    }

    #[test]
    fn array_order_preserved() {
        let v = json!([3, 1, 2]);
        assert_eq!(canonical_value_bytes(&v), b"[3,1,2]");
    }

    #[test]
    fn object_keys_sorted() {
        let v = json!({"b": 1, "a": 2});
        assert_eq!(canonical_value_bytes(&v), b"{\"a\":2,\"b\":1}");
    }
}

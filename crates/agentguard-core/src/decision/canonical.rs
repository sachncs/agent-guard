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

    #[test]
    fn nested_keys_sorted_recursively() {
        let v = json!({"outer": {"z": 1, "a": 2}, "first": 3});
        let out = canonical_value_bytes(&v);
        // Both outer and inner keys are sorted.
        assert!(out.starts_with(b"{\"first\":3,\"outer\":{\"a\":2,\"z\":1}}"));
    }

    #[test]
    fn primitives_render_canonically() {
        assert_eq!(canonical_value_bytes(&json!(null)), b"null");
        assert_eq!(canonical_value_bytes(&json!(true)), b"true");
        assert_eq!(canonical_value_bytes(&json!(false)), b"false");
        assert_eq!(canonical_value_bytes(&json!(42)), b"42");
        assert_eq!(canonical_value_bytes(&json!("hello")), b"\"hello\"");
    }

    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Canonicalization is deterministic: same input always produces
            /// the same bytes.
            #[test]
            fn canonical_is_deterministic(
                keys in proptest::collection::hash_set("[a-z]{1,4}", 1..6),
                values in proptest::collection::vec(0i64..100, 1..6)
            ) {
                let mut obj = serde_json::Map::new();
                for (i, k) in keys.iter().enumerate() {
                    obj.insert(k.clone(), serde_json::json!(values.get(i).copied().unwrap_or(0)));
                }
                let v1 = canonical_value_bytes(&serde_json::Value::Object(obj.clone()));
                let v2 = canonical_value_bytes(&serde_json::Value::Object(obj.clone()));
                prop_assert_eq!(v1, v2);
            }

            /// Hashes are pure: same input → same hash (when the chain head
            /// is the same).
            #[test]
            fn hash_chain_pure(
                payload in "[a-zA-Z0-9]{1,32}"
            ) {
                use crate::decision::chain::HashChain;
                let chain1 = HashChain::new(b"root");
                let chain2 = HashChain::new(b"root");
                let h1 = chain1.append(payload.as_bytes());
                let h2 = chain2.append(payload.as_bytes());
                prop_assert_eq!(h1, h2);
            }
        }
    }
}

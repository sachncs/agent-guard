//! Canonical JSON serialization (simplified RFC 8785).
//!
//! We don't implement the full RFC 8785 (which covers numeric edge cases);
//! instead we sort object keys deterministically and emit the same shape as
//! `serde_json::to_vec`. This is sufficient for hash-chain inputs where the
//! producer and verifier are both Rust processes.

use crate::error::Result;
use serde::Serialize;
use serde_json::{Map, Value};
use std::io::Write;

/// Serialize `value` as canonical JSON: object keys sorted lexicographically.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let v = serde_json::to_value(value)?;
    let mut buf = Vec::new();
    write_canonical_value(&mut buf, &v)?;
    Ok(buf)
}

/// Write a `Value` as canonical JSON into a `Write`.
///
/// Streams output to the writer rather than building an intermediate `String`.
/// This is the hot path for hash-chain append: every byte written to disk
/// flows through this function, so reducing allocations matters at scale.
pub fn write_canonical_value<W: Write>(w: &mut W, v: &Value) -> Result<()> {
    match v {
        Value::Null => w.write_all(b"null").map_err(into_err)?,
        Value::Bool(b) => {
            let s = if *b { "true" } else { "false" };
            w.write_all(s.as_bytes()).map_err(into_err)?;
        }
        Value::Number(n) => {
            w.write_all(n.to_string().as_bytes()).map_err(into_err)?;
        }
        Value::String(s) => {
            serde_json::to_writer(w, s)
                .map_err(|e| Error::Other(format!("serialize string: {}", e)))?;
        }
        Value::Array(arr) => {
            w.write_all(b"[").map_err(into_err)?;
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    w.write_all(b",").map_err(into_err)?;
                }
                write_canonical_value(w, item)?;
            }
            w.write_all(b"]").map_err(into_err)?;
        }
        Value::Object(obj) => write_canonical_object(w, obj)?,
    }
    Ok(())
}

fn write_canonical_object<W: Write>(w: &mut W, obj: &Map<String, Value>) -> Result<()> {
    // Sort keys lexicographically.
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();

    w.write_all(b"{").map_err(into_err)?;
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            w.write_all(b",").map_err(into_err)?;
        }
        // Borrow the writer mutably for the json call.
        serde_json::to_writer(&mut *w, k)
            .map_err(|e| Error::Other(format!("serialize key: {}", e)))?;
        w.write_all(b":").map_err(into_err)?;
        write_canonical_value(w, &obj[*k])?;
    }
    w.write_all(b"}").map_err(into_err)?;
    Ok(())
}

fn into_err(e: std::io::Error) -> Error {
    Error::Io(e.to_string())
}

use crate::error::Error;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_object_canonical() {
        let v = json!({});
        let mut buf = Vec::new();
        write_canonical_value(&mut buf, &v).unwrap();
        assert_eq!(buf, b"{}");
    }

    #[test]
    fn array_order_preserved() {
        let v = json!([3, 1, 2]);
        let mut buf = Vec::new();
        write_canonical_value(&mut buf, &v).unwrap();
        assert_eq!(buf, b"[3,1,2]");
    }

    #[test]
    fn object_keys_sorted() {
        let v = json!({"b": 1, "a": 2});
        let mut buf = Vec::new();
        write_canonical_value(&mut buf, &v).unwrap();
        assert_eq!(buf, b"{\"a\":2,\"b\":1}");
    }

    #[test]
    fn streaming_matches_allocating() {
        // The streaming API must produce identical output to the
        // Vec<u8>-allocating API.
        let v = json!({"a": 1, "b": [1, 2, 3], "c": null, "d": "x"});
        let allocating = canonical_json(&v).unwrap();
        let mut streaming = Vec::new();
        write_canonical_value(&mut streaming, &v).unwrap();
        assert_eq!(allocating, streaming);
    }

    #[test]
    fn nested_keys_sorted_recursively() {
        let v = json!({"outer": {"z": 1, "a": 2}, "first": 3});
        let mut buf = Vec::new();
        write_canonical_value(&mut buf, &v).unwrap();
        // Both outer and inner keys are sorted.
        assert!(buf.starts_with(b"{\"first\":3,\"outer\":{\"a\":2,\"z\":1}}"));
    }

    #[test]
    fn primitives_render_canonically() {
        let cases: Vec<(serde_json::Value, Vec<u8>)> = vec![
            (json!(null), b"null".to_vec()),
            (json!(true), b"true".to_vec()),
            (json!(false), b"false".to_vec()),
            (json!(42), b"42".to_vec()),
            (json!("hello"), b"\"hello\"".to_vec()),
        ];
        for (val, expected) in cases {
            let mut buf = Vec::new();
            write_canonical_value(&mut buf, &val).unwrap();
            assert_eq!(buf, expected, "value {val:?}");
        }
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
                let v1 = canonical_json(&serde_json::Value::Object(obj.clone())).unwrap();
                let v2 = canonical_json(&serde_json::Value::Object(obj.clone())).unwrap();
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

            /// The streaming canonical writer must agree with the
            /// allocating `canonical_json` for arbitrary inputs.
            #[test]
            fn streaming_equals_allocating(
                keys in proptest::collection::hash_set("[a-z]{1,4}", 1..6),
                values in proptest::collection::vec(any::<i64>(), 1..6)
            ) {
                let mut obj = serde_json::Map::new();
                for (i, k) in keys.iter().enumerate() {
                    obj.insert(k.clone(), serde_json::json!(values.get(i).copied().unwrap_or(0)));
                }
                let v = serde_json::Value::Object(obj);
                let allocating = canonical_json(&v).unwrap();
                let mut streaming = Vec::new();
                write_canonical_value(&mut streaming, &v).unwrap();
                prop_assert_eq!(allocating, streaming);
            }
        }
    }
}

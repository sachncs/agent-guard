//! HMAC-SHA256 hash chain for tamper-evident audit records.
//!
//! Each record's hash is `HMAC(root_key, prev_hash || canonical_json(record))`.
//! Genesis records use `prev_hash = [0; 32]`.

use crate::error::{Error, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

/// Length of a chain hash in bytes (32 = SHA-256 output).
pub const HASH_LEN: usize = 32;

/// A unique identifier for one chain (helps when multiple chains coexist).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainId(pub uuid::Uuid);

impl ChainId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for ChainId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A live hash chain: holds the root key and current head hash.
///
/// Cloning is cheap (Arc'd). Thread-safe via `parking_lot::Mutex` on the head.
#[derive(Clone)]
pub struct HashChain {
    inner: Arc<HashChainInner>,
}

struct HashChainInner {
    root: Vec<u8>,
    head: parking_lot::Mutex<[u8; HASH_LEN]>,
    id: ChainId,
}

impl std::fmt::Debug for HashChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashChain")
            .field("id", &self.inner.id)
            .field("head", &"<32 bytes>")
            .finish()
    }
}

impl HashChain {
    /// Construct a new chain with the given root key and all-zero head.
    pub fn new(root_key: &[u8]) -> Self {
        Self {
            inner: Arc::new(HashChainInner {
                root: root_key.to_vec(),
                head: parking_lot::Mutex::new([0u8; HASH_LEN]),
                id: ChainId::new(),
            }),
        }
    }

    /// Construct a chain that resumes from a given head hash (for verification).
    pub fn resume(root_key: &[u8], head: [u8; HASH_LEN], id: ChainId) -> Self {
        Self {
            inner: Arc::new(HashChainInner {
                root: root_key.to_vec(),
                head: parking_lot::Mutex::new(head),
                id,
            }),
        }
    }

    pub fn id(&self) -> ChainId {
        self.inner.id
    }

    pub fn head(&self) -> [u8; HASH_LEN] {
        *self.inner.head.lock()
    }

    /// Append a record: returns (prev_hash, new_hash).
    ///
    /// The canonical record bytes should be the canonical JSON serialization
    /// of the record (see [`crate::decision::canonical`]).
    pub fn append(&self, canonical_record: &[u8]) -> ([u8; HASH_LEN], [u8; HASH_LEN]) {
        let prev = *self.inner.head.lock();
        let mut mac =
            HmacSha256::new_from_slice(&self.inner.root).expect("HMAC accepts any key length");
        mac.update(&prev);
        mac.update(canonical_record);
        let new_hash: [u8; HASH_LEN] = mac.finalize().into_bytes().into();
        *self.inner.head.lock() = new_hash;
        (prev, new_hash)
    }

    /// Verify a single record's hash matches what the chain would produce.
    pub fn verify(
        &self,
        canonical_record: &[u8],
        claimed_prev: &[u8; HASH_LEN],
        claimed_hash: &[u8; HASH_LEN],
    ) -> Result<()> {
        let mut mac = HmacSha256::new_from_slice(&self.inner.root)
            .map_err(|e| Error::Other(format!("hmac init: {}", e)))?;
        mac.update(claimed_prev);
        mac.update(canonical_record);
        let expected: [u8; HASH_LEN] = mac.finalize().into_bytes().into();
        if &expected != claimed_hash {
            return Err(Error::Other(format!(
                "hash mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(claimed_hash)
            )));
        }
        Ok(())
    }

    /// Verify a full chain given the records. The first record's `prev_hash`
    /// must equal `[0; HASH_LEN]`. The last record's hash must equal the
    /// current head.
    pub fn verify_chain(
        &self,
        records: &[(Vec<u8>, [u8; HASH_LEN], [u8; HASH_LEN])],
    ) -> Result<()> {
        let mut expected_prev = [0u8; HASH_LEN];
        for (i, (canonical, prev, hash)) in records.iter().enumerate() {
            if prev != &expected_prev {
                return Err(Error::Other(format!(
                    "record {}: prev_hash mismatch: expected {}, got {}",
                    i,
                    hex::encode(expected_prev),
                    hex::encode(prev)
                )));
            }
            self.verify(canonical, prev, hash)
                .map_err(|e| Error::Other(format!("record {}: {}", i, e)))?;
            expected_prev = *hash;
        }
        let head = self.head();
        if head != expected_prev {
            return Err(Error::Other(format!(
                "chain head mismatch: expected {}, got {}",
                hex::encode(expected_prev),
                hex::encode(head)
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::canonical::canonical_json;
    use serde_json::json;

    #[test]
    fn chain_appends_and_head_advances() {
        let chain = HashChain::new(b"root-key");
        let (_, h1) = chain.append(b"record-1");
        assert_ne!(h1, [0u8; HASH_LEN]);
        let (prev2, h2) = chain.append(b"record-2");
        assert_eq!(prev2, h1);
        assert_ne!(h2, h1);
    }

    #[test]
    fn chain_verifies_its_own_records() {
        let chain = HashChain::new(b"root-key");
        let (p1, h1) = chain.append(b"record-1");
        let (p2, h2) = chain.append(b"record-2");
        chain
            .verify_chain(&[
                (b"record-1".to_vec(), p1, h1),
                (b"record-2".to_vec(), p2, h2),
            ])
            .unwrap();
    }

    #[test]
    fn chain_detects_tampering() {
        let chain = HashChain::new(b"root-key");
        let (p1, h1) = chain.append(b"record-1");
        // Tamper with the record bytes.
        let res = chain.verify(&b"record-1-tampered".to_vec(), &p1, &h1);
        assert!(res.is_err());
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let v = json!({"b": 1, "a": 2, "c": [3, 2, 1]});
        let s1 = canonical_json(&v).unwrap();
        let s2 = canonical_json(&v).unwrap();
        assert_eq!(s1, s2);
        // Recreate the same value with a different field order.
        let v2 = json!({"a": 2, "c": [3, 2, 1], "b": 1});
        let s3 = canonical_json(&v2).unwrap();
        assert_eq!(s1, s3, "canonical JSON must sort keys");
    }

    #[test]
    fn chain_with_canonical_json_verifies() {
        let chain = HashChain::new(b"root-key");
        let v = json!({"decision": "allow", "principal": "alice"});
        let canonical = canonical_json(&v).unwrap();
        let (p, h) = chain.append(&canonical);
        chain.verify(&canonical, &p, &h).unwrap();
    }
}

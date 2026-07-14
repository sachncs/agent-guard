//! Append-only JSONL decision log writer with optional HMAC hash chaining.

use crate::authorize::Decision;
use crate::decision::canonical::canonical_json;
use crate::decision::chain::{ChainId, HashChain, HASH_LEN};
use crate::decision::record::DecisionRecord;
use crate::error::{Error, Result};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Thread-safe append-only JSONL log.
///
/// When constructed via [`DecisionLog::open`], the log is plain JSONL.
/// When constructed via [`DecisionLog::open_with_chain`], each record is
/// chained to the previous via HMAC-SHA256.
pub struct DecisionLog {
    mode: LogMode,
}

enum LogMode {
    Plain(Mutex<Option<File>>),
    Chained {
        file: Mutex<Option<File>>,
        chain: HashChain,
    },
}

impl DecisionLog {
    /// Open a plain (un-chained) JSONL log at `path`.
    ///
    /// # Errors
    /// Returns `Error::Io` if the path cannot be opened for append or if
    /// the parent directory cannot be created.
    ///
    /// # Examples
    /// ```
    /// use agentguard_core::decision::DecisionLog;
    /// let log = DecisionLog::open("/tmp/audit.jsonl").unwrap();
    /// ```
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open_internal(path.into(), None)
    }

    /// Open a hash-chained JSONL log at `path` with the given root key.
    ///
    /// # Errors
    /// Returns `Error::Io` if the path cannot be opened or the parent
    /// directory cannot be created.
    ///
    /// # Examples
    /// ```
    /// use agentguard_core::decision::DecisionLog;
    /// let log = DecisionLog::open_with_chain("/tmp/audit.jsonl", b"root-key").unwrap();
    /// ```
    pub fn open_with_chain(path: impl Into<PathBuf>, root_key: &[u8]) -> Result<Self> {
        Self::open_internal(path.into(), Some(root_key.to_vec()))
    }

    fn open_internal(path: PathBuf, root_key: Option<Vec<u8>>) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = OpenOptions::new().create(true).append(true).open(&path)?;
        match root_key {
            None => Ok(Self {
                mode: LogMode::Plain(Mutex::new(Some(f))),
            }),
            Some(key) => {
                let chain = HashChain::new(&key);
                // Resume the chain from the file's last record, so each
                // subprocess invocation picks up where the last left off.
                let _ = chain.load_head_from_file(&path);
                Ok(Self {
                    mode: LogMode::Chained {
                        file: Mutex::new(Some(f)),
                        chain,
                    },
                })
            }
        }
    }

    pub fn default_path() -> PathBuf {
        PathBuf::from(".audit/decisions.jsonl")
    }

    pub fn chain_id(&self) -> Option<ChainId> {
        match &self.mode {
            LogMode::Plain(_) => None,
            LogMode::Chained { chain, .. } => Some(chain.id()),
        }
    }

    /// Append a record. When the log is chained, the record is signed.
    ///
    /// # Errors
    /// Returns `Error::Json` if `rec` cannot be serialized, or
    /// `Error::Io` if the write fails.
    pub fn append(&self, rec: &DecisionRecord) -> Result<()> {
        let canonical = canonical_json(rec)?;
        match &self.mode {
            LogMode::Plain(file) => {
                let line = serde_json::to_string(rec)?;
                let mut guard = file.lock().expect("DecisionLog mutex poisoned");
                if let Some(f) = guard.as_mut() {
                    writeln!(f, "{}", line)?;
                    f.flush()?;
                }
            }
            LogMode::Chained { file, chain } => {
                let (prev, hash) = chain.append(&canonical);
                let chained = ChainedRecord {
                    prev_hash: hex::encode(prev),
                    record_hash: hex::encode(hash),
                    chain_id: chain.id(),
                    record: rec.clone(),
                };
                let line = serde_json::to_string(&chained)?;
                let mut guard = file.lock().expect("DecisionLog mutex poisoned");
                if let Some(f) = guard.as_mut() {
                    writeln!(f, "{}", line)?;
                    f.flush()?;
                }
            }
        }
        Ok(())
    }

    pub fn append_decision(&self, d: &Decision) -> Result<()> {
        let rec = DecisionRecord::from_decision(d, None, None);
        self.append(&rec)
    }

    pub fn read_all(path: impl AsRef<Path>) -> Result<Vec<DecisionRecord>> {
        Self::read_all_with_format(path, false)
    }

    pub fn read_all_chained(path: impl AsRef<Path>) -> Result<Vec<ChainedRecord>> {
        let f = File::open(path.as_ref())?;
        let r = BufReader::new(f);
        let mut out = Vec::new();
        for line in r.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let rec: ChainedRecord = serde_json::from_str(&line)?;
            out.push(rec);
        }
        Ok(out)
    }

    fn read_all_with_format(path: impl AsRef<Path>, _chained: bool) -> Result<Vec<DecisionRecord>> {
        let f = File::open(path.as_ref())?;
        let r = BufReader::new(f);
        let mut out = Vec::new();
        for line in r.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            // Try as ChainedRecord first, fall back to plain.
            let rec: DecisionRecord = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(_) => {
                    // Try unwrapping as ChainedRecord.
                    let chained: ChainedRecord = serde_json::from_str(&line)?;
                    chained.record
                }
            };
            out.push(rec);
        }
        Ok(out)
    }

    /// Verify the entire audit log against the root key.
    ///
    /// Reads every record from `path`, checks the HMAC chain, and returns
    /// the chain head. Returns an error if any record is tampered.
    ///
    /// # Errors
    /// Returns `Error::Other` (formatted string) on parse failure, hash
    /// mismatch, or chain head mismatch.
    pub fn verify_chain(path: impl AsRef<Path>, root_key: &[u8]) -> Result<ChainId> {
        let records = Self::read_all_chained(path)?;
        let mut chain_id = None;
        let mut entries = Vec::new();
        for cr in &records {
            if chain_id.is_none() {
                chain_id = Some(cr.chain_id);
            }
            let canonical = canonical_json(&cr.record)?;
            let prev = parse_hex32(&cr.prev_hash)?;
            let hash = parse_hex32(&cr.record_hash)?;
            entries.push((canonical, prev, hash));
        }
        let chain = HashChain::resume(
            root_key,
            entries
                .last()
                .map(|(_, _, h)| *h)
                .unwrap_or([0u8; HASH_LEN]),
            chain_id.unwrap_or_default(),
        );
        chain.verify_chain(&entries)?;
        Ok(chain_id.unwrap_or_default())
    }
}

fn parse_hex32(s: &str) -> Result<[u8; HASH_LEN]> {
    let bytes = hex::decode(s).map_err(|e| Error::Other(format!("hex: {}", e)))?;
    if bytes.len() != HASH_LEN {
        return Err(Error::Other(format!(
            "expected {} bytes, got {}",
            HASH_LEN,
            bytes.len()
        )));
    }
    let mut arr = [0u8; HASH_LEN];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// A record with chain metadata. On disk, the chain fields are at the top
/// level alongside the record fields.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainedRecord {
    pub prev_hash: String,
    pub record_hash: String,
    pub chain_id: ChainId,
    #[serde(flatten)]
    pub record: DecisionRecord,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_log_writes_no_chain_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.jsonl");
        let log = DecisionLog::open(&path).unwrap();
        assert!(log.chain_id().is_none());
    }

    #[test]
    fn chained_log_assigns_chain_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chained.jsonl");
        let log = DecisionLog::open_with_chain(&path, b"root").unwrap();
        assert!(log.chain_id().is_some());
    }
}

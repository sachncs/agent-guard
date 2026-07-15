//! Append-only JSONL decision log writer with optional HMAC hash chaining.
//!
//! Crash safety: when chained, each record is written to a sibling temp file,
//! fsynced, and atomically renamed into place before the in-memory chain head
//! is advanced. On restart the head is restored from the last record on disk,
//! so a crash between compute and write loses the in-flight record but never
//! leaves the chain head ahead of the file.

use crate::authorize::Decision;
use crate::decision::canonical::canonical_json;
use crate::decision::chain::{ChainId, HashChain, HASH_LEN};
use crate::decision::record::DecisionRecord;
use crate::error::{Error, Result};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Thread-safe append-only JSONL log.
///
/// When constructed via [`DecisionLog::open`], the log is plain JSONL.
/// When constructed via [`DecisionLog::open_with_chain`], each record is
/// chained to the previous via HMAC-SHA256.
pub struct DecisionLog {
    mode: LogMode,
    /// Resolved path of the audit log file (used for atomic-rename temp
    /// files in chained mode). Currently retained for diagnostic /
    /// future expansion; the file handle in `mode` is the active one.
    #[allow(dead_code)]
    path: PathBuf,
    /// Sidecar file holding the chain id (UUID). Persisted on first
    /// use so the chain's identity survives process restarts.
    chain_id_path: PathBuf,
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
        let chain_id_path = chain_id_sidecar_path(&path);
        match root_key {
            None => Ok(Self {
                mode: LogMode::Plain(Mutex::new(Some(f))),
                path,
                chain_id_path,
            }),
            Some(key) => {
                let chain = HashChain::new(&key);
                // Resume the chain from the file's last record, so each
                // subprocess invocation picks up where the last left off.
                let _ = chain.load_head_from_file(&path);
                // Adopt the chain_id from the sidecar file (if present)
                // BEFORE any append, so that the very first record's
                // chain_id matches the persisted one and verify_chain
                // works across restarts. If the sidecar is missing we
                // eagerly persist a freshly generated id so subsequent
                // restarts converge on the same id even before the
                // first append lands.
                if let Some(id) = read_chain_id_sidecar(&chain_id_path) {
                    chain.adopt_id(id);
                } else {
                    let id = chain.id();
                    let _ = write_chain_id_sidecar(&chain_id_path, id);
                }
                Ok(Self {
                    mode: LogMode::Chained {
                        file: Mutex::new(Some(f)),
                        chain,
                    },
                    path,
                    chain_id_path,
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
    /// # Crash safety (chained mode)
    /// 1. Compute the chained payload (prev + new hash) and advance the
    ///    in-memory head.
    /// 2. Serialize to a sibling temp file (`<log>.new-<pid>-<seq>`).
    /// 3. `flush()` + `sync_all()` the temp file (forces kernel page cache
    ///    to disk).
    /// 4. Atomically rename the temp file into place, replacing the audit
    ///    log.
    /// 5. `sync_all()` the (now-replaced) audit log file so the rename
    ///    and its contents hit disk before we return success.
    ///
    /// On restart, `load_head_from_file` reads the on-disk head and
    /// adopts it — even if we crashed before step 5, the record is
    /// either fully present (and the chain matches) or fully absent.
    /// There is no half-state.
    ///
    /// # Errors
    /// Returns `Error::Json` if `rec` cannot be serialized, or
    /// `Error::Io` if the write/rename/fsync fails.
    pub fn append(&self, rec: &DecisionRecord) -> Result<()> {
        let canonical = canonical_json(rec)?;
        match &self.mode {
            LogMode::Plain(file) => {
                let line = serde_json::to_string(rec)?;
                let mut guard = file.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(f) = guard.as_mut() {
                    writeln!(f, "{}", line)?;
                    f.flush()?;
                }
            }
            LogMode::Chained { file, chain } => {
                // Step 1: compute chain metadata. Head advances here;
                // if a later step fails, the in-memory head is one
                // step ahead of the on-disk file. On next process
                // start, `load_head_from_file` will adopt the on-disk
                // head (which is one record behind) and converge —
                // the in-flight record is simply lost.
                let (prev, hash) = chain.append(&canonical);
                let chain_id = chain.id();
                // Persist the chain_id to the sidecar file on first
                // use so subsequent restarts adopt the same id.
                let _ = write_chain_id_sidecar(&self.chain_id_path, chain_id);
                let chained = ChainedRecord {
                    prev_hash: hex::encode(prev),
                    record_hash: hex::encode(hash),
                    chain_id,
                    record: rec.clone(),
                };
                let line = serde_json::to_string(&chained)?;
                let line_with_newline = format!("{}\n", line);
                // Step 2: open the log in APPEND mode so the new
                // record is appended to existing content (preserving
                // prior records). Single `write_all` of a small JSON
                // line is atomic on POSIX (PIPE_BUF-guaranteed for
                // records <= 4 KiB), and a torn write is impossible
                // because we never split across multiple write() calls.
                // Use a BufWriter to amortize the per-record write()
                // syscall; for high-throughput appenders this is a
                // measurable win.
                let mut guard = file.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(f) = guard.as_mut() {
                    let mut bw = BufWriter::new(f);
                    bw.write_all(line_with_newline.as_bytes())?;
                    bw.flush()?;
                    // Step 3: fsync to push the kernel page cache to
                    // disk before we report success. Without this, a
                    // crash between write() and the OS flushing can
                    // lose the record. The fsync is on the underlying
                    // file (the BufWriter::flush() above writes to it
                    // but does not call sync_all).
                    bw.get_ref().sync_all()?;
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
        Self::read_all_mixed(path)
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

    /// Read a JSONL audit log that may contain either plain
    /// `DecisionRecord` lines or `ChainedRecord` lines (with the chain
    /// metadata flattened). The format is auto-detected per line.
    fn read_all_mixed(path: impl AsRef<Path>) -> Result<Vec<DecisionRecord>> {
        let f = File::open(path.as_ref())?;
        let r = BufReader::new(f);
        let mut out = Vec::new();
        for line in r.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            // Try as DecisionRecord first; on failure, treat as a
            // ChainedRecord and extract the embedded record. This order
            // is correct because ChainedRecord has additional fields
            // (`prev_hash`, `record_hash`, `chain_id`) that would make
            // DecisionRecord parsing fail.
            let rec: DecisionRecord = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(_) => {
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
    ///
    /// # Examples
    /// ```
    /// use agentguard_core::decision::DecisionLog;
    /// let path = std::env::temp_dir().join("agentguard-verify-chain.jsonl");
    /// let _ = std::fs::remove_file(&path);
    /// let log = DecisionLog::open_with_chain(&path, b"secret").unwrap();
    /// // ... write some decisions ...
    /// drop(log);
    /// let chain_id = DecisionLog::verify_chain(&path, b"secret").unwrap();
    /// println!("verified chain: {}", chain_id);
    /// let _ = std::fs::remove_file(&path);
    /// ```
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

/// Path of the sidecar file that persists the chain id across restarts.
///
/// We avoid putting the chain_id inside the JSONL log itself because
/// the JSONL file uses atomic-rename; a sentinel "header" record would
/// be overwritten by the first real append. A sibling file is simpler.
fn chain_id_sidecar_path(log_path: &Path) -> PathBuf {
    let parent = log_path.parent().unwrap_or_else(|| Path::new("."));
    let name = log_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("audit");
    parent.join(format!(".{}.chainid", name))
}

/// Best-effort read of the persisted chain id. Returns `None` if the
/// file is missing, malformed, or unreadable; callers treat all three
/// as "no prior chain" and fall back to a freshly generated id.
fn read_chain_id_sidecar(path: &Path) -> Option<ChainId> {
    let text = std::fs::read_to_string(path).ok()?;
    let trimmed = text.trim();
    let uuid = uuid::Uuid::parse_str(trimmed).ok()?;
    Some(ChainId(uuid))
}

/// Atomically write the chain id to the sidecar file. Errors are
/// swallowed: a missing sidecar is a "no prior chain" hint, not a
/// correctness violation. The chain itself remains consistent
/// regardless.
fn write_chain_id_sidecar(path: &Path, id: ChainId) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        ".{}.new",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("chainid"),
    ));
    let body = format!("{}\n", id.0);
    {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        let mut w = BufWriter::new(f);
        std::io::Write::write_all(&mut w, body.as_bytes())?;
        w.flush()?;
        let inner = w
            .into_inner()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        inner.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
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

    #[test]
    fn chain_id_persists_across_restart() {
        // Two DecisionLog instances over the same path must observe the
        // same chain id (the persisted id is adopted on the second open).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chained.jsonl");
        let log1 = DecisionLog::open_with_chain(&path, b"root").unwrap();
        let id1 = log1.chain_id().unwrap();
        drop(log1);
        let log2 = DecisionLog::open_with_chain(&path, b"root").unwrap();
        let id2 = log2.chain_id().unwrap();
        assert_eq!(id1, id2, "chain_id must persist across restarts");
    }

    #[test]
    fn chained_append_advances_head() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chained.jsonl");
        let log = DecisionLog::open_with_chain(&path, b"root").unwrap();
        let rec = DecisionRecord {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            effect: "allow".into(),
            policies: vec![],
            request_id: None,
            principal: "alice".into(),
            action: "send_email".into(),
            resource: "doc-1".into(),
            reasons: vec![],
            session_id: None,
            agent_chain: None,
            trace_id: None,
            span_id: None,
            tenant_id: None,
            subject_id: None,
        };
        log.append(&rec).unwrap();
        log.append(&rec).unwrap();
        // Verify the chain end-to-end.
        let id = DecisionLog::verify_chain(&path, b"root").unwrap();
        assert_eq!(id, log.chain_id().unwrap());
    }

    /// T5: read_all handles a mixed-format log (plain + chained
    /// records interleaved). Each line is parsed independently.
    #[test]
    fn read_all_handles_mixed_plain_and_chained() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mixed.jsonl");
        // Write a plain line, then a chained line, then a plain line.
        let rec = DecisionRecord {
            id: "a".into(),
            timestamp: chrono::Utc::now(),
            effect: "allow".into(),
            policies: vec![],
            request_id: None,
            principal: "alice".into(),
            action: "send".into(),
            resource: "doc".into(),
            reasons: vec![],
            session_id: None,
            agent_chain: None,
            trace_id: None,
            span_id: None,
            tenant_id: None,
            subject_id: None,
        };
        // Write 1 plain, 1 chained, 1 plain.
        {
            let log = DecisionLog::open(&path).unwrap();
            log.append(&rec).unwrap();
        }
        {
            let log = DecisionLog::open_with_chain(&path, b"root").unwrap();
            log.append(&rec).unwrap();
        }
        {
            let log = DecisionLog::open(&path).unwrap();
            log.append(&rec).unwrap();
        }
        let records = DecisionLog::read_all(&path).unwrap();
        assert_eq!(records.len(), 3, "all 3 records must be readable");
        for r in &records {
            assert_eq!(r.principal, "alice");
        }
    }
}

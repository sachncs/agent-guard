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

/// Rotation policy for a [`DecisionLog`].
///
/// When the active file's size exceeds `max_bytes`, the next append
/// renames it to a timestamped sibling and opens a fresh file. The
/// chain id sidecar is preserved per file so a verifier can walk
/// rotated logs in order. Default behaviour (no rotation) is the
/// backward-compatible path; supply `Some(RotationConfig { .. })` to
/// `open_with_chain` / `open` to enable it.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Rotate when the active file exceeds this many bytes.
    pub max_bytes: u64,
}

impl RotationConfig {
    /// Parse a positive audit-log rotation threshold in bytes.
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        match value.parse::<u64>() {
            Ok(max_bytes) if max_bytes > 0 => Ok(Self { max_bytes }),
            _ => Err("must be a positive integer when set".to_owned()),
        }
    }

    /// Read `AGENTGUARD_AUDIT_MAX_BYTES` from the environment, rejecting
    /// malformed or non-Unicode values instead of silently disabling rotation.
    pub fn try_from_env() -> std::result::Result<Option<Self>, String> {
        match std::env::var("AGENTGUARD_AUDIT_MAX_BYTES") {
            Ok(value) => Self::parse(&value).map(Some),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err("must be valid Unicode".to_owned()),
        }
    }

    /// Lossy legacy environment parser. Prefer [`Self::try_from_env`].
    #[deprecated(note = "use try_from_env to report invalid configuration")]
    pub fn from_env() -> Option<Self> {
        Self::try_from_env().ok().flatten()
    }
}

/// Thread-safe append-only JSONL log.
///
/// When constructed via [`DecisionLog::open`], the log is plain JSONL.
/// When constructed via [`DecisionLog::open_with_chain`], each record is
/// chained to the previous via HMAC-SHA256.
pub struct DecisionLog {
    mode: LogMode,
    /// Resolved path of the audit log file. Used by tracing
    /// instrumentation on every append and exposed via [`Self::path`]
    /// for diagnostics and tests.
    path: PathBuf,
    /// Sidecar file holding the chain id (UUID). Persisted on first
    /// use so the chain's identity survives process restarts.
    chain_id_path: PathBuf,
    /// Optional rotation policy. When `Some`, append() rotates the
    /// active file once its size exceeds `max_bytes`.
    rotation: Option<RotationConfig>,
    /// Serializes threshold checks and renames so concurrent appenders cannot
    /// both attempt to rotate the same active file.
    rotation_lock: Mutex<()>,
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
        Self::open_internal(path.into(), None, None)
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
        Self::open_internal(path.into(), Some(root_key.to_vec()), None)
    }

    /// Open with an explicit rotation policy. When the active file
    /// exceeds `rotation.max_bytes`, the next append renames it to a
    /// timestamped sibling and opens a fresh active file.
    pub fn open_with_rotation(
        path: impl Into<PathBuf>,
        root_key: Option<&[u8]>,
        rotation: RotationConfig,
    ) -> Result<Self> {
        Self::open_internal(path.into(), root_key.map(|k| k.to_vec()), Some(rotation))
    }

    fn open_internal(
        path: PathBuf,
        root_key: Option<Vec<u8>>,
        rotation: Option<RotationConfig>,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = open_audit_file(&path)?;
        let chain_id_path = chain_id_sidecar_path(&path);
        match root_key {
            None => Ok(Self {
                mode: LogMode::Plain(Mutex::new(Some(f))),
                path,
                chain_id_path,
                rotation,
                rotation_lock: Mutex::new(()),
            }),
            Some(key) => {
                let chain = HashChain::new(&key);
                // Authenticate all persisted segments before accepting new
                // writes. Restoring only the final hash would let a validly
                // formatted edit survive startup and be extended as if it
                // were trustworthy.
                let mut persisted_paths = rotated_logs(&path)?;
                persisted_paths.push(path.clone());
                verify_chain_paths(&persisted_paths, &key).map_err(|e| {
                    Error::Other(format!(
                        "refusing to open invalid chained audit log {}: {e}",
                        path.display()
                    ))
                })?;
                // Resume from the active file's last record. A crash can
                // happen after rotation renamed the old file but before the
                // next append populated the new active file; in that case,
                // recover from the newest rotated segment instead of
                // silently starting a disconnected chain.
                let head_path = if std::fs::metadata(&path)
                    .map(|metadata| metadata.len() == 0)
                    .unwrap_or(true)
                {
                    latest_rotated_log(&path)?.unwrap_or_else(|| path.clone())
                } else {
                    path.clone()
                };
                // Corruption is reported (not silently ignored) so the
                // operator is alerted to tampering or partial writes.
                chain.load_head_from_file(&head_path).map_err(|e| {
                    Error::Other(format!(
                        "refusing to open corrupt chained audit log {}: {e}",
                        head_path.display()
                    ))
                })?;
                // Adopt the chain_id from the sidecar file (if present)
                // BEFORE any append, so that the very first record's
                // chain_id matches the persisted one and verify_chain
                // works across restarts. If the sidecar is missing we
                // eagerly persist a freshly generated id so subsequent
                // restarts converge on the same id even before the
                // first append lands.
                let prior_sidecar = if head_path == path {
                    chain_id_path.clone()
                } else {
                    chain_id_sidecar_path(&head_path)
                };
                if let Some(id) = read_chain_id_sidecar(&prior_sidecar) {
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
                    rotation,
                    rotation_lock: Mutex::new(()),
                })
            }
        }
    }

    pub fn default_path() -> PathBuf {
        PathBuf::from(".audit/decisions.jsonl")
    }

    /// Rotate the active file when it crosses `rotation.max_bytes`.
    /// Cheap no-op when rotation is disabled or the threshold has not
    /// been reached. Called at the top of [`Self::append`].
    fn rotate_if_needed(&self) -> Result<()> {
        let _rotation_guard = self.rotation_lock.lock().unwrap_or_else(|e| e.into_inner());
        let rotation = match &self.rotation {
            Some(r) => r,
            None => return Ok(()),
        };
        let size = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if size < rotation.max_bytes {
            return Ok(());
        }
        self.rotate_inner()
    }

    /// Force a rotation: rename the active file to a timestamped
    /// sibling in the same directory and reopen the active file. The
    /// chain id sidecar is moved alongside so the rotated file's
    /// chain id is preserved.
    pub fn rotate(&self) -> Result<()> {
        let _rotation_guard = self.rotation_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.rotate_inner()
    }

    fn rotate_inner(&self) -> Result<()> {
        let now = chrono::Utc::now();
        let ts = format!(
            "{}{:06}Z",
            now.format("%Y%m%dT%H%M%S"),
            now.timestamp_subsec_micros()
        );
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let stem = self
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("decisions");
        let ext = self
            .path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("jsonl");
        let mut rotated = parent.join(format!("{stem}-{ts}.{ext}"));
        let mut suffix = 1u32;
        while rotated.exists() {
            rotated = parent.join(format!("{stem}-{ts}-{suffix}.{ext}"));
            suffix = suffix.saturating_add(1);
        }

        // Hold the file lock across close + rename + reopen. Otherwise a
        // concurrent append can observe the temporary `None` and silently
        // discard its record while rotation is in progress.
        match &self.mode {
            LogMode::Plain(file) => {
                let mut guard = file.lock().unwrap_or_else(|e| e.into_inner());
                *guard = None;
                *guard = Some(self.reopen_rotated(&rotated)?);
            }
            LogMode::Chained { file, chain } => {
                let mut guard = file.lock().unwrap_or_else(|e| e.into_inner());
                *guard = None;
                let f = self.reopen_rotated(&rotated)?;
                // Re-load chain head from the rotated file so the new
                // active file chains from where the rotated one left
                // off. The chain id is preserved through the sidecar
                // rename above.
                chain
                    .load_head_from_file(&rotated)
                    .map_err(|e| Error::Io(format!("reload chain after rotate: {e}")))?;
                if let Some(id) = read_chain_id_sidecar(&chain_id_sidecar_path(&rotated)) {
                    chain.adopt_id(id);
                }
                *guard = Some(f);
            }
        }
        tracing::info!(
            active = %self.path.display(),
            rotated = %rotated.display(),
            "rotated audit log"
        );
        Ok(())
    }

    fn reopen_rotated(&self, rotated: &Path) -> Result<File> {
        std::fs::rename(&self.path, rotated).map_err(|e| {
            Error::Io(format!(
                "rotate {} -> {}: {}",
                self.path.display(),
                rotated.display(),
                e
            ))
        })?;
        if self.chain_id_path.exists() {
            let rotated_sidecar = chain_id_sidecar_path(rotated);
            let _ = std::fs::rename(&self.chain_id_path, rotated_sidecar);
        }
        open_audit_file(&self.path).map_err(Error::from)
    }

    /// Path the log was opened at. Useful for `agentguard doctor` and
    /// for tests that need to assert where the audit was written.
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn chain_id(&self) -> Option<ChainId> {
        match &self.mode {
            LogMode::Plain(_) => None,
            LogMode::Chained { chain, .. } => Some(chain.id()),
        }
    }

    /// Whether the writer still has a usable active file handle. This turns
    /// permanent append failures into an observable readiness signal instead
    /// of leaving the service healthy while every decision fails to audit.
    pub fn is_healthy(&self) -> bool {
        match &self.mode {
            LogMode::Plain(file) | LogMode::Chained { file, .. } => {
                file.lock().map(|guard| guard.is_some()).unwrap_or(false)
            }
        }
    }

    /// Append a record. When the log is chained, the record is signed.
    ///
    /// # Crash safety (chained mode)
    /// The file lock is held for the entire critical section:
    /// 1. Compute the chained payload (prev + new hash).
    /// 2. `write_all` + `flush` + `sync_all` the JSON line to the log
    ///    file. The next startup validates the complete tail before
    ///    accepting new writes, so a torn or malformed final record fails
    ///    closed instead of silently starting a disconnected chain.
    /// 3. The chain head advances only after step 2 succeeds. On
    ///    failure, the chain stays at the previous head and the next
    ///    caller retries from the same state.
    ///
    /// On restart, `load_head_from_file` reads the on-disk head and
    /// adopts it — even if we crashed between the `sync_all` and the
    /// head advance, the record is fully on disk and the chain
    /// matches.
    ///
    /// # Errors
    /// Returns `Error::Json` if `rec` cannot be serialized, or
    /// `Error::Io` if the write/fsync fails.
    #[tracing::instrument(skip_all, fields(path = %self.path.display()))]
    pub fn append(&self, rec: &DecisionRecord) -> Result<()> {
        let canonical = canonical_json(rec)?;
        // Rotate before writing if the active file has crossed the
        // size threshold. Cheap no-op when nothing is configured.
        self.rotate_if_needed()?;
        match &self.mode {
            LogMode::Plain(file) => {
                let mut line = serde_json::to_vec(rec)?;
                line.push(b'\n');
                let mut guard = file.lock().unwrap_or_else(|e| e.into_inner());
                let Some(f) = guard.as_mut() else {
                    return Err(Error::Io(
                        "audit log is unavailable after a prior storage failure".into(),
                    ));
                };
                let write_result = write_line_durably(f, &line);
                if let Err(error) = write_result {
                    // A failed write may have left a partial JSONL record.
                    // Poison this handle so no later caller can mistake a
                    // missing or ambiguous record for a successful append.
                    *guard = None;
                    return Err(Error::from(error));
                }
            }
            LogMode::Chained { file, chain } => {
                // Lock the file first (the chain head lock is acquired
                // inside `try_append_with_io`); ordering is
                // file -> chain so the call graph cannot deadlock.
                let chain_id = chain.id();
                // Persist the chain_id to the sidecar file on first
                // use so subsequent restarts adopt the same id.
                let _ = write_chain_id_sidecar(&self.chain_id_path, chain_id);
                let mut guard = file.lock().unwrap_or_else(|e| e.into_inner());
                let Some(f) = guard.as_mut() else {
                    return Err(Error::Io(
                        "audit log is unavailable after a prior storage failure".into(),
                    ));
                };
                // Atomic: chain head advances only on a successful
                // write_all + sync_all. A failed or uncertain write poisons
                // this handle, preventing later appends from silently
                // diverging from the on-disk chain.
                if let Err(error) =
                    chain.try_append_with_io(&canonical, |prev, new_hash| -> std::io::Result<()> {
                        let chained = ChainedRecord {
                            prev_hash: hex::encode(prev),
                            record_hash: hex::encode(new_hash),
                            chain_id,
                            record: rec.clone(),
                        };
                        let mut line_with_newline = serde_json::to_vec(&chained)?;
                        line_with_newline.push(b'\n');
                        // Write directly to the File; the kernel
                        // page cache is the buffering layer. A
                        // per-call BufWriter::new allocation was
                        // dropped (50-80 ns saved per append).
                        write_line_durably(f, &line_with_newline)
                    })
                {
                    *guard = None;
                    return Err(Error::from(error));
                }
            }
        }
        Ok(())
    }

    /// Convenience wrapper around [`Self::append`] that constructs the
    /// `DecisionRecord` from a `Decision` with empty session/chain
    /// metadata. Use [`Self::append`] directly to attach session
    /// ID or delegation chain.
    ///
    /// # Errors
    /// Same as [`Self::append`].
    pub fn append_decision(&self, d: &Decision) -> Result<()> {
        let rec = DecisionRecord::from_decision(d, None, None);
        self.append(&rec)
    }

    /// Read every record from the audit log and its timestamped rotation
    /// siblings in chronological order, accepting either plain or chained
    /// records (mixed log files are supported; older records may pre-date
    /// chain metadata).
    ///
    /// # Errors
    /// Returns `Error::Io` if the file cannot be read, `Error::Json`
    /// if a record cannot be parsed.
    pub fn read_all(path: impl AsRef<Path>) -> Result<Vec<DecisionRecord>> {
        let path = path.as_ref();
        let mut paths = rotated_logs(path)?;
        paths.push(path.to_path_buf());
        Self::read_all_mixed_paths(&paths)
    }

    /// Read every record from the audit log, requiring all records to
    /// carry chain metadata. A plain (non-chained) record in the log
    /// surfaces as `Error::Json` with the row number.
    ///
    /// # Errors
    /// Returns `Error::Io` if the file cannot be read, `Error::Json`
    /// if a record cannot be parsed or is missing chain metadata.
    pub fn read_all_chained(path: impl AsRef<Path>) -> Result<Vec<ChainedRecord>> {
        let f = open_existing_audit_file(path.as_ref())?;
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
    fn read_all_mixed_paths(paths: &[PathBuf]) -> Result<Vec<DecisionRecord>> {
        let mut out = Vec::new();
        for path in paths {
            let f = open_existing_audit_file(path)?;
            let r = BufReader::new(f);
            for (idx, line) in r.lines().enumerate() {
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
                    Err(plain_err) => match serde_json::from_str::<ChainedRecord>(&line) {
                        Ok(chained) => chained.record,
                        Err(chained_err) => {
                            return Err(Error::Json(format!(
                                "{} line {}: not a DecisionRecord ({plain_err}); \
                                 also not a ChainedRecord ({chained_err})",
                                path.display(),
                                idx + 1
                            )));
                        }
                    },
                };
                out.push(rec);
            }
        }
        Ok(out)
    }

    /// Verify the entire audit log against the root key.
    ///
    /// Reads every record from `path` and its timestamped rotation siblings,
    /// checks the continuous HMAC chain, and returns the chain id. Returns
    /// an error if a record is malformed, tampered, or belongs to another
    /// chain.
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
        let path = path.as_ref();
        let mut paths = rotated_logs(path)?;
        paths.push(path.to_path_buf());
        verify_chain_paths(&paths, root_key)
    }
}

fn verify_chain_paths(paths: &[PathBuf], root_key: &[u8]) -> Result<ChainId> {
    let mut chain_id = None;
    let mut entries = Vec::new();
    for path in paths {
        for record in DecisionLog::read_all_chained(path)? {
            if let Some(expected) = chain_id {
                if record.chain_id != expected {
                    return Err(Error::Other(format!(
                        "chain id mismatch in {}: expected {}, got {}",
                        path.display(),
                        expected,
                        record.chain_id
                    )));
                }
            } else {
                chain_id = Some(record.chain_id);
            }
            let canonical = canonical_json(&record.record)?;
            let prev = parse_hex32(&record.prev_hash)?;
            let hash = parse_hex32(&record.record_hash)?;
            entries.push((canonical, prev, hash));
        }
    }
    let id = chain_id.unwrap_or_default();
    let head = entries
        .last()
        .map(|(_, _, hash)| *hash)
        .unwrap_or([0u8; HASH_LEN]);
    HashChain::resume(root_key, head, id).verify_chain(&entries)?;
    Ok(id)
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

/// List timestamped rotations for `log_path` in chronological order. Rotation
/// timestamps are UTC and fixed-width; collision suffixes are sorted
/// numerically so `-10` follows `-9`, not `-1`.
fn rotated_logs(log_path: &Path) -> Result<Vec<PathBuf>> {
    let parent = log_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = log_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("decisions");
    let extension = log_path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("jsonl");
    let prefix = format!("{stem}-");
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let path = entry.path();
        let rotation_suffix = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|stem| stem.strip_prefix(&prefix));
        if rotation_suffix.is_some_and(is_rotation_filename)
            && path.extension().and_then(|s| s.to_str()) == Some(extension)
            && entry.file_type()?.is_file()
        {
            candidates.push(path);
        }
    }
    candidates.sort_by_key(|path| rotation_order(path, &prefix));
    Ok(candidates)
}

fn rotation_order(path: &Path, prefix: &str) -> (String, u32) {
    let suffix = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| stem.strip_prefix(prefix))
        .unwrap_or_default();
    let (timestamp, collision) = suffix
        .split_once('-')
        .map_or((suffix, None), |(timestamp, collision)| {
            (timestamp, Some(collision))
        });
    let collision = collision
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    (timestamp.to_string(), collision)
}

fn latest_rotated_log(log_path: &Path) -> Result<Option<PathBuf>> {
    Ok(rotated_logs(log_path)?.pop())
}

/// Open an existing audit path only when it is a regular file. Checking the
/// directory entry before opening prevents FIFOs and device nodes from
/// blocking startup or audit inspection; the descriptor check also catches
/// replacement races that resolve to a non-regular file.
fn open_existing_audit_file(path: &Path) -> std::io::Result<File> {
    validate_audit_path(path)?;
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("audit path must be a regular file: {}", path.display()),
        ));
    }
    Ok(file)
}

/// Open (or create) the active append-only audit file, rejecting symlinks,
/// FIFOs, sockets, and device nodes instead of treating them as durable files.
fn open_audit_file(path: &Path) -> std::io::Result<File> {
    validate_audit_path(path)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("audit path must be a regular file: {}", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn validate_audit_path(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "audit path must be a regular file, not a symlink or special file: {}",
                path.display()
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Append one complete JSONL record and durably persist it. If a write or
/// sync fails after a partial append, truncate back to the previous boundary
/// before returning the original error. Callers poison the handle regardless,
/// since a failed fsync leaves durability uncertain even after rollback.
fn write_line_durably(file: &mut File, line: &[u8]) -> std::io::Result<()> {
    let original_len = file.metadata()?.len();
    if let Err(write_error) = file.write_all(line).and_then(|()| file.sync_all()) {
        return match file.set_len(original_len).and_then(|()| file.sync_all()) {
            Ok(()) => Err(write_error),
            Err(rollback_error) => Err(std::io::Error::new(
                rollback_error.kind(),
                format!("audit append failed ({write_error}); rollback failed ({rollback_error})"),
            )),
        };
    }
    Ok(())
}

fn is_rotation_filename(suffix: &str) -> bool {
    let timestamp = suffix
        .split_once('-')
        .map_or(suffix, |(timestamp, _)| timestamp);
    let bytes = timestamp.as_bytes();
    if bytes.len() != 22 || bytes[8] != b'T' || bytes[21] != b'Z' {
        return false;
    }
    if !bytes
        .iter()
        .enumerate()
        .all(|(index, byte)| index == 8 || index == 21 || byte.is_ascii_digit())
    {
        return false;
    }
    match suffix.split_once('-') {
        None => true,
        Some((_, collision_suffix)) => collision_suffix
            .parse::<u32>()
            .is_ok_and(|number| number > 0),
    }
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
    fn chained_log_refuses_corrupt_existing_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.jsonl");
        std::fs::write(&path, "{\"not\":\"a chained record\"}\n").unwrap();

        let err = match DecisionLog::open_with_chain(&path, b"root") {
            Ok(_) => panic!("corrupt chained audit log must be rejected"),
            Err(err) => err,
        };
        assert!(err
            .to_string()
            .contains("refusing to open invalid chained audit log"));
    }

    #[test]
    fn chained_log_refuses_valid_json_tampering_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tampered.jsonl");
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
        {
            let log = DecisionLog::open_with_chain(&path, b"root").unwrap();
            log.append(&rec).unwrap();
        }

        let mut line: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        line["principal"] = serde_json::Value::String("mallory".into());
        std::fs::write(&path, format!("{line}\n")).unwrap();

        let err = match DecisionLog::open_with_chain(&path, b"root") {
            Ok(_) => panic!("tampered chained audit log must be rejected"),
            Err(err) => err,
        };
        assert!(err
            .to_string()
            .contains("refusing to open invalid chained audit log"));
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

    #[cfg(unix)]
    #[test]
    fn failed_audit_write_poisoning_is_reported_not_silently_dropped() {
        let full = Path::new("/dev/full");
        if !full.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let rec = DecisionRecord {
            id: "storage-failure".into(),
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

        for chained in [false, true] {
            let path = dir.path().join(format!("write-failure-{chained}.jsonl"));
            let log = if chained {
                DecisionLog::open_with_chain(&path, b"test-root").unwrap()
            } else {
                DecisionLog::open(&path).unwrap()
            };
            // Inject the special device only after normal startup has
            // validated and opened a regular audit file. Reading /dev/full
            // yields an unbounded zero stream on Linux, so using it as the
            // chained startup path would test an infinite scan, not a failed
            // append.
            let failing_writer = OpenOptions::new().write(true).open(full).unwrap();
            match &log.mode {
                LogMode::Plain(file) | LogMode::Chained { file, .. } => {
                    *file.lock().unwrap() = Some(failing_writer);
                }
            }

            assert!(
                log.append(&rec).is_err(),
                "first storage failure must surface"
            );
            assert!(!log.is_healthy(), "failed writer must become unhealthy");
            let retry = log.append(&rec).unwrap_err();
            assert!(retry
                .to_string()
                .contains("unavailable after a prior storage failure"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn audit_open_rejects_special_files_and_symlinks_before_reading_them() {
        let full = Path::new("/dev/full");
        if !full.exists() {
            return;
        }
        let plain_error = DecisionLog::open(full)
            .err()
            .expect("special files must not be accepted as plain audit logs");
        assert!(plain_error.to_string().contains("regular file"));

        let chained_error = DecisionLog::open_with_chain(full, b"test-root")
            .err()
            .expect("special files must be rejected before verification");
        assert!(chained_error.to_string().contains("regular file"));

        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("audit.jsonl");
        std::os::unix::fs::symlink(full, &link).unwrap();
        let symlink_error = DecisionLog::open_with_chain(&link, b"test-root")
            .err()
            .expect("symlinks must be rejected before verification");
        assert!(symlink_error.to_string().contains("regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn audit_log_permissions_are_private_on_open() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let _log = DecisionLog::open(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "audit records must not be group/world readable"
        );
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
        // Build one plain and one chained line independently, then combine
        // them. A chained writer must reject an existing plain tail; mixed
        // logs remain supported for read-only inspection/export.
        {
            let log = DecisionLog::open(&path).unwrap();
            log.append(&rec).unwrap();
        }
        {
            let chained_path = dir.path().join("chained-only.jsonl");
            let log = DecisionLog::open_with_chain(&chained_path, b"root").unwrap();
            log.append(&rec).unwrap();
            let chained_line = std::fs::read_to_string(chained_path).unwrap();
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(chained_line.as_bytes())
                .unwrap();
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

    #[test]
    fn read_all_mixed_surfaces_both_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.jsonl");
        // One valid plain record, then a truncated line that is neither
        // a DecisionRecord nor a ChainedRecord.
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
        let log = DecisionLog::open(&path).unwrap();
        log.append(&rec).unwrap();
        // Append a corrupt line.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"this\":\"is broken")
            .unwrap();
        let err = DecisionLog::read_all(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("line 2"),
            "error must reference the offending line number: {msg}"
        );
        assert!(
            msg.contains("DecisionRecord"),
            "error must mention the DecisionRecord parse failure: {msg}"
        );
        assert!(
            msg.contains("ChainedRecord"),
            "error must mention the ChainedRecord parse failure: {msg}"
        );
    }

    #[test]
    fn rotation_config_requires_a_positive_integer() {
        assert_eq!(
            RotationConfig::parse("1048576").unwrap().max_bytes,
            1_048_576
        );
        for value in ["0", "-1", "many", ""] {
            assert!(RotationConfig::parse(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn rotation_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rotating.jsonl");
        let log =
            DecisionLog::open_with_rotation(&path, None::<&[u8]>, RotationConfig { max_bytes: 64 })
                .unwrap();
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
        for _ in 0..5 {
            log.append(&rec).unwrap();
        }
        // 5 records * ~300 bytes each > 64 bytes threshold; at least
        // one rotation must have happened.
        let rotated: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("rotating-"))
            .collect();
        assert!(
            !rotated.is_empty(),
            "expected at least one rotated file in {}",
            dir.path().display()
        );
        assert!(path.exists(), "active file must still be open");
    }

    #[test]
    fn rotated_log_discovery_ignores_lookalike_files() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("decisions.jsonl");
        let real = dir.path().join("decisions-20260923T123456000000Z.jsonl");
        std::fs::write(dir.path().join("decisions-backup.jsonl"), b"not a rotation").unwrap();
        std::fs::write(
            dir.path().join("decisions-20260923T123456Z.jsonl"),
            b"bad timestamp",
        )
        .unwrap();
        std::fs::write(&real, b"rotation").unwrap();

        assert_eq!(rotated_logs(&active).unwrap(), vec![real]);
    }

    #[test]
    fn rotated_log_discovery_orders_collision_suffixes_numerically() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("decisions.jsonl");
        let expected = [
            "decisions-20260923T123456000000Z.jsonl",
            "decisions-20260923T123456000000Z-2.jsonl",
            "decisions-20260923T123456000000Z-10.jsonl",
        ]
        .map(|name| dir.path().join(name));
        for path in expected.iter().rev() {
            std::fs::write(path, b"segment").unwrap();
        }

        assert_eq!(rotated_logs(&active).unwrap(), expected);
    }

    #[test]
    fn chained_rotation_recovers_head_after_restart_before_next_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chained.jsonl");
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

        let first_id = {
            let log = DecisionLog::open_with_rotation(
                &path,
                Some(b"root"),
                RotationConfig {
                    max_bytes: u64::MAX,
                },
            )
            .unwrap();
            log.append(&rec).unwrap();
            let id = log.chain_id().unwrap();
            log.rotate().unwrap();
            id
        };

        // The process has restarted while the active file is still empty.
        let log = DecisionLog::open_with_rotation(
            &path,
            Some(b"root"),
            RotationConfig {
                max_bytes: u64::MAX,
            },
        )
        .unwrap();
        assert_eq!(log.chain_id().unwrap(), first_id);
        log.append(&rec).unwrap();

        let rotated = latest_rotated_log(&path).unwrap().unwrap();
        let before = DecisionLog::read_all_chained(&rotated).unwrap();
        let after = DecisionLog::read_all_chained(&path).unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(after.len(), 1);
        assert_eq!(before[0].chain_id, after[0].chain_id);
        assert_eq!(before[0].record_hash, after[0].prev_hash);
        assert_eq!(DecisionLog::verify_chain(&path, b"root").unwrap(), first_id);
        assert_eq!(DecisionLog::read_all(&path).unwrap().len(), 2);
    }

    #[test]
    fn concurrent_rotation_does_not_lose_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("concurrent.jsonl");
        let log = std::sync::Arc::new(
            DecisionLog::open_with_rotation(&path, None::<&[u8]>, RotationConfig { max_bytes: 64 })
                .unwrap(),
        );
        let rec = DecisionRecord {
            id: "concurrent".into(),
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
        let mut workers = Vec::new();
        for _ in 0..4 {
            let log = std::sync::Arc::clone(&log);
            let rec = rec.clone();
            workers.push(std::thread::spawn(move || {
                for _ in 0..25 {
                    log.append(&rec).unwrap();
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }

        let total_records: usize = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".jsonl"))
            .map(|entry| {
                std::fs::read_to_string(entry.path())
                    .unwrap()
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count()
            })
            .sum();
        assert_eq!(total_records, 100);
    }
}

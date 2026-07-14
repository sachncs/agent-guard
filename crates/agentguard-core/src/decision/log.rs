//! Append-only JSONL decision log writer.

use crate::authorize::Decision;
use crate::decision::record::DecisionRecord;
use crate::error::Result;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Thread-safe append-only JSONL log.
pub struct DecisionLog {
    inner: Mutex<Option<File>>,
}

impl DecisionLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let _path = path.into();
        if let Some(parent) = _path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = OpenOptions::new().create(true).append(true).open(&_path)?;
        Ok(Self {
            inner: Mutex::new(Some(f)),
        })
    }

    pub fn default_path() -> PathBuf {
        PathBuf::from(".audit/decisions.jsonl")
    }

    pub fn append(&self, rec: &DecisionRecord) -> Result<()> {
        let line = serde_json::to_string(rec)?;
        let mut guard = self.inner.lock().unwrap();
        if let Some(f) = guard.as_mut() {
            writeln!(f, "{}", line)?;
            f.flush()?;
        }
        Ok(())
    }

    pub fn append_decision(&self, d: &Decision) -> Result<()> {
        let rec = DecisionRecord::from_decision(d, None, None);
        self.append(&rec)
    }

    pub fn read_all(path: impl AsRef<Path>) -> Result<Vec<DecisionRecord>> {
        let f = File::open(path.as_ref())?;
        let r = BufReader::new(f);
        let mut out = Vec::new();
        for line in r.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let rec: DecisionRecord = serde_json::from_str(&line)?;
            out.push(rec);
        }
        Ok(out)
    }
}

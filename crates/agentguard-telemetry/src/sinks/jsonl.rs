//! JSONL sink — appends each event as one JSON line.

use crate::sink::{Sink, SinkError, SinkEvent};
use async_trait::async_trait;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Append-only JSONL sink.
///
/// Thread-safe: a single `Arc<JsonlSink>` can be shared across threads.
pub struct JsonlSink {
    path: PathBuf,
    inner: Mutex<Option<File>>,
}

impl JsonlSink {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            inner: Mutex::new(Some(f)),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait]
impl Sink for JsonlSink {
    fn name(&self) -> &str {
        "jsonl"
    }

    async fn emit(&self, event: &SinkEvent) -> Result<(), SinkError> {
        let line = serde_json::to_string(event)?;
        // ponytail: see StdoutSink — recover from a poisoned
        // mutex instead of panicking the worker.
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(f) = guard.as_mut() {
            writeln!(f, "{}", line)?;
            f.flush()?;
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), SinkError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        *guard = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::SinkEvent;
    use tempfile::tempdir;

    #[tokio::test]
    async fn jsonl_sink_writes_one_line_per_event() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let sink = JsonlSink::open(&path).unwrap();

        for i in 0..3 {
            let event = SinkEvent::decision(
                if i % 2 == 0 { "allow" } else { "deny" },
                "alice",
                "send_email",
                "alice@acme",
                vec![format!("policy{i}")],
                vec![],
                1000 + i as u64,
            );
            sink.emit(&event).await.unwrap();
        }
        sink.flush().await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        for (i, line) in lines.iter().enumerate() {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["kind"]["principal"], "alice");
            assert_eq!(parsed["kind"]["action"], "send_email");
            assert_eq!(
                parsed["kind"]["effect"],
                if i % 2 == 0 { "allow" } else { "deny" }
            );
        }
    }
}

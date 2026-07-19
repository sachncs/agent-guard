//! Stdout sink — prints events as pretty JSON for local debugging.

use crate::sink::{Sink, SinkError, SinkEvent};
use async_trait::async_trait;
use std::io::Write;
use std::sync::Mutex;

/// Sink that writes each event to stdout, pretty-printed.
///
/// The internal `Mutex` serializes writes so output doesn't interleave.
pub struct StdoutSink {
    inner: Mutex<std::io::Stdout>,
}

impl StdoutSink {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(std::io::stdout()),
        }
    }
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Sink for StdoutSink {
    fn name(&self) -> &str {
        "stdout"
    }

    async fn emit(&self, event: &SinkEvent) -> Result<(), SinkError> {
        let json = serde_json::to_string_pretty(event)?;
        // ponytail: a poisoned mutex would normally panic the
        // thread; recover by acquiring the inner state anyway
        // (the data is still consistent — only the recovery
        // metadata was lost).
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        writeln!(guard, "{}", json)?;
        guard.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stdout_sink_serializes_event() {
        let sink = StdoutSink::new();
        let event = SinkEvent::decision("allow", "alice", "x", "y", vec![], vec![], 100);
        // Smoke test: just ensure it doesn't error.
        sink.emit(&event).await.unwrap();
    }
}

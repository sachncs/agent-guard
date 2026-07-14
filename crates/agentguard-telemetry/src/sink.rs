// TODO(stage-1): full Sink trait + JSONL/Stdout/OTLP sinks. See stages/STAGE-1-telemetry.md.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SinkError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("send error: {0}")]
    Send(String),
    #[error("other: {0}")]
    Other(String),
}

/// A telemetry event emitted by agentguard.
///
/// Carries kind-specific payloads. The `serde_json::Value` fields keep this
/// crate decoupled from agentguard-core's exact schema during stage-1
/// scaffolding; Stage 1.7 wires typed payloads in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkEvent {
    #[serde(rename = "type")]
    pub kind: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_micros: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

impl SinkEvent {
    pub fn decision(decision: serde_json::Value) -> Self {
        Self {
            kind: "decision".into(),
            timestamp: chrono::Utc::now(),
            decision: Some(decision),
            trace_id: None,
            span_id: None,
            duration_micros: None,
            tenant_id: None,
        }
    }
}

/// Sink for telemetry events.
///
/// Implementations should be cheap to clone (typically `Arc<Sink>`) and
/// must be safe to call from multiple threads concurrently.
#[async_trait]
pub trait Sink: Send + Sync {
    /// Stable identifier for this sink (e.g. `"jsonl"`, `"stdout"`, `"otlp"`).
    fn name(&self) -> &str;

    /// Emit one event. Implementations should be non-blocking when possible.
    async fn emit(&self, event: &SinkEvent) -> Result<(), SinkError>;

    /// Flush any buffered events. Default is no-op.
    async fn flush(&self) -> Result<(), SinkError> {
        Ok(())
    }

    /// Release resources (close file handles, flush OTLP exporter, etc).
    /// Default is no-op.
    async fn shutdown(&self) -> Result<(), SinkError> {
        Ok(())
    }
}

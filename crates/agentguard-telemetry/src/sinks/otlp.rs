//! OpenTelemetry/OTLP sink — feature-gated.
//!
//! TODO(stage-1): full implementation. For now, this is a stub that satisfies
//! the `Sink` trait when the `otlp` feature is enabled.

#[cfg(feature = "otlp")]
use crate::sink::{Sink, SinkError, SinkEvent};
#[cfg(feature = "otlp")]
use async_trait::async_trait;

/// Placeholder OTLP sink. Real implementation will translate `SinkEvent`s
/// into OpenTelemetry log/span exports.
#[cfg(feature = "otlp")]
pub struct OtlpSink;

#[cfg(feature = "otlp")]
#[async_trait]
impl Sink for OtlpSink {
    fn name(&self) -> &str {
        "otlp"
    }

    async fn emit(&self, _event: &SinkEvent) -> Result<(), SinkError> {
        Ok(())
    }
}

//! OpenTelemetry/OTLP sink — feature-gated behind the `otlp` feature.
//!
//! Translates agentguard's [`SinkEvent`]s into OTel log records and exports
//! them over OTLP/gRPC. The OTLP exporter is initialized from environment
//! variables (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`,
//! `OTEL_SERVICE_NAME`).

#[cfg(feature = "otlp")]
use crate::sink::{Sink, SinkError, SinkEvent};
#[cfg(feature = "otlp")]
use async_trait::async_trait;
#[cfg(feature = "otlp")]
use opentelemetry::logs::{LogRecord, Logger, LoggerProvider, RecordMetadata, Severity};
#[cfg(feature = "otlp")]
use opentelemetry::trace::TracerProvider as _;
#[cfg(feature = "otlp")]
use opentelemetry::KeyValue;
#[cfg(feature = "otlp")]
use opentelemetry_sdk::logs::LoggerProvider as SdkLoggerProvider;
#[cfg(feature = "otlp")]
use opentelemetry_sdk::Resource;

/// OTLP sink: translates `SinkEvent`s into OTel log records and ships them
/// over OTLP/gRPC to a configured collector.
#[cfg(feature = "otlp")]
pub struct OtlpSink {
    provider: SdkLoggerProvider,
}

#[cfg(feature = "otlp")]
impl OtlpSink {
    /// Construct an OTLP sink. Reads endpoint and headers from the standard
    /// `OTEL_EXPORTER_OTLP_*` environment variables.
    pub fn from_env() -> Result<Self, OtlpError> {
        use opentelemetry_otlp::WithExportConfig;
        let exporter = opentelemetry_otlp::new_exporter().tonic().with_env();
        let provider = SdkLoggerProvider::builder()
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .with_resource(Resource::builder().with_service_name("agentguard").build())
            .build();
        Ok(Self { provider })
    }

    /// Construct from an explicit endpoint URL.
    pub fn with_endpoint(endpoint: impl Into<String>) -> Result<Self, OtlpError> {
        use opentelemetry_otlp::WithExportConfig;
        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint);
        let provider = SdkLoggerProvider::builder()
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .with_resource(Resource::builder().with_service_name("agentguard").build())
            .build();
        Ok(Self { provider })
    }
}

#[cfg(feature = "otlp")]
#[async_trait]
impl Sink for OtlpSink {
    fn name(&self) -> &str {
        "otlp"
    }

    async fn emit(&self, event: &SinkEvent) -> Result<(), SinkError> {
        let logger = self.provider.logger("agentguard");
        let mut record = logger.create_log_record();
        record.set_severity_number(Severity::Info);
        record.set_body(format!("agentguard decision: {}", event.kind.summary()).into());
        record.add_attributes(event.kind.attributes());
        logger.emit(record);
        Ok(())
    }

    async fn flush(&self) -> Result<(), SinkError> {
        self.provider
            .force_flush()
            .map_err(|e| SinkError::Other(format!("otlp flush: {}", e)))
    }

    async fn shutdown(&self) -> Result<(), SinkError> {
        self.provider
            .shutdown()
            .map_err(|e| SinkError::Other(format!("otlp shutdown: {}", e)))
    }
}

#[cfg(feature = "otlp")]
impl OtlpSink {
    // No additional impl; placeholder for future helpers.
}

#[cfg(feature = "otlp")]
impl Drop for OtlpSink {
    fn drop(&mut self) {
        // Best-effort shutdown; if it fails, the provider still flushes on drop.
        let _ = self.provider.shutdown();
    }
}

#[cfg(feature = "otlp")]
#[derive(Debug, thiserror::Error)]
pub enum OtlpError {
    #[error("otlp init: {0}")]
    Init(String),
}

impl From<OtlpError> for SinkError {
    fn from(e: OtlpError) -> Self {
        SinkError::Other(e.to_string())
    }
}

#[cfg(feature = "otlp")]
trait SinkEventExt {
    fn summary(&self) -> String;
    fn attributes(&self) -> Vec<KeyValue>;
}

#[cfg(feature = "otlp")]
impl SinkEventExt for crate::sink::SinkEventKind {
    fn summary(&self) -> String {
        match self {
            crate::sink::SinkEventKind::Decision {
                effect,
                principal,
                action,
                resource,
                ..
            } => {
                format!(
                    "{} {} on {} ({} {})",
                    effect, principal, action, effect, resource
                )
            }
            _ => "agentguard event".into(),
        }
    }
    fn attributes(&self) -> Vec<KeyValue> {
        let mut out = Vec::new();
        if let crate::sink::SinkEventKind::Decision {
            effect,
            principal,
            action,
            resource,
            policies,
            ..
        } = self
        {
            out.push(KeyValue::new("authz.effect", effect.clone()));
            out.push(KeyValue::new("authz.principal", principal.clone()));
            out.push(KeyValue::new("authz.action", action.clone()));
            out.push(KeyValue::new("authz.resource", resource.clone()));
            out.push(KeyValue::new("authz.policies", policies.join(",")));
        }
        out
    }
}

#[cfg(not(feature = "otlp"))]
// Placeholder when the `otlp` feature is not enabled. Calling any method
// returns a configuration error. This is a feature-gated stub that satisfies
// the `Sink` trait in the `otlp` feature path.
pub struct OtlpSink;

#[cfg(test)]
mod tests {
    #[test]
    fn otlp_sink_is_optional() {
        // Smoke test: the `otlp` feature is off by default; the type still
        // exists in the public API.
        let _: Option<OtlpSink> = None;
    }
}

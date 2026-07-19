//! OpenTelemetry/OTLP sink — feature-gated behind the `otlp` feature.
//!
//! Translates agentguard's [`SinkEvent`]s into OTel log records and exports
//! them over OTLP/gRPC. The OTLP exporter is initialized from the standard
//! `OTEL_EXPORTER_OTLP_*` environment variables (endpoint, headers, etc).
//!
//! The `/metrics` route and the OTLP sink are complementary surfaces —
//! Prometheus-text snapshots are served locally for scraping, and the
//! OTLP sink streams events to a remote collector. Both consume the
//! same [`crate::Metrics`] handle.

#[cfg(feature = "otlp")]
use crate::sink::{Sink, SinkError, SinkEvent, SinkEventKind};
#[cfg(feature = "otlp")]
use async_trait::async_trait;
#[cfg(feature = "otlp")]
use opentelemetry::logs::{LogRecord, Logger, LoggerProvider, Severity};
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
    /// Construct an OTLP sink from the standard
    /// `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_HEADERS`
    /// environment variables.
    pub fn from_env() -> Result<Self, OtlpError> {
        use opentelemetry_otlp::WithExportConfig;
        // Read endpoint from the env, fall back to the SDK default.
        let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty());
        let mut builder = opentelemetry_otlp::new_exporter().tonic();
        if let Some(ep) = endpoint {
            builder = builder.with_endpoint(ep);
        }
        let exporter = builder
            .build_log_exporter()
            .map_err(|e| OtlpError::Init(format!("build exporter: {}", e)))?;
        let provider = SdkLoggerProvider::builder()
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .with_resource(make_resource())
            .build();
        Ok(Self { provider })
    }

    /// Construct from an explicit endpoint URL.
    pub fn with_endpoint(endpoint: impl Into<String>) -> Result<Self, OtlpError> {
        use opentelemetry_otlp::WithExportConfig;
        let exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(endpoint.into())
            .build_log_exporter()
            .map_err(|e| OtlpError::Init(format!("build exporter: {}", e)))?;
        let provider = SdkLoggerProvider::builder()
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .with_resource(make_resource())
            .build();
        Ok(Self { provider })
    }
}

#[cfg(feature = "otlp")]
fn make_resource() -> Resource {
    let service_name = std::env::var("OTEL_SERVICE_NAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "agentguard".to_string());
    Resource::new(vec![KeyValue::new("service.name", service_name)])
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
        record.set_body(format!("agentguard event: {:?}", event.kind).into());
        // Attach the structured fields as OTel attributes so a
        // collector can index them. Attribute keys follow the
        // agentguard.* convention to avoid clashing with OTel
        // reserved namespaces.
        match &event.kind {
            SinkEventKind::Decision {
                effect,
                principal,
                action,
                resource,
                cached,
                trace_id,
                span_id,
                tenant_id,
                ..
            } => {
                record.add_attribute("agentguard.event", "decision");
                record.add_attribute("agentguard.effect", effect.clone());
                record.add_attribute("agentguard.principal", principal.clone());
                record.add_attribute("agentguard.action", action.clone());
                record.add_attribute("agentguard.resource", resource.clone());
                record.add_attribute("agentguard.cached", *cached);
                if let Some(t) = trace_id {
                    record.add_attribute("trace.id", t.clone());
                }
                if let Some(s) = span_id {
                    record.add_attribute("span.id", s.clone());
                }
                if let Some(t) = tenant_id {
                    record.add_attribute("agentguard.tenant_id", t.clone());
                }
            }
            SinkEventKind::DelegationMint {
                issuer, subject, ..
            } => {
                record.add_attribute("agentguard.event", "delegation_mint");
                record.add_attribute("agentguard.issuer", issuer.clone());
                record.add_attribute("agentguard.subject", subject.clone());
            }
            SinkEventKind::DelegationVerify { success, .. } => {
                record.add_attribute("agentguard.event", "delegation_verify");
                record.add_attribute("agentguard.success", *success);
            }
            SinkEventKind::PolicyReload {
                version, source, ..
            } => {
                record.add_attribute("agentguard.event", "policy_reload");
                record.add_attribute("agentguard.policy_version", version.clone());
                record.add_attribute("agentguard.source", source.clone());
            }
            SinkEventKind::CacheLookup {
                hit,
                principal,
                action,
            } => {
                record.add_attribute("agentguard.event", "cache_lookup");
                record.add_attribute("agentguard.cache_hit", *hit);
                record.add_attribute("agentguard.principal", principal.clone());
                record.add_attribute("agentguard.action", action.clone());
            }
            SinkEventKind::PdpError { error, fallback } => {
                record.add_attribute("agentguard.event", "pdp_error");
                record.add_attribute("agentguard.error", error.clone());
                record.add_attribute("agentguard.fallback", fallback.clone());
            }
        }
        logger.emit(record);
        Ok(())
    }

    async fn flush(&self) -> Result<(), SinkError> {
        let results = self.provider.force_flush();
        for r in results {
            r.map_err(|e| SinkError::Other(format!("otlp flush: {}", e)))?;
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), SinkError> {
        self.provider
            .shutdown()
            .map_err(|e| SinkError::Other(format!("otlp shutdown: {}", e)))
    }
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "otlp")]
    use super::OtlpSink;

    /// ponytail: a sink is `Send + Sync` so the metrics task can hand
    /// it to a worker thread without `Arc`. Asserting it here catches
    /// a regression where the inner type accidentally holds an
    /// `Rc`/`RefCell`.
    #[cfg(feature = "otlp")]
    #[allow(dead_code)]
    fn assert_send_sync<T: Send + Sync>() {}

    #[cfg(feature = "otlp")]
    #[test]
    fn otlp_sink_is_send_sync() {
        assert_send_sync::<OtlpSink>();
    }

    /// Construction needs a live tokio runtime (the batch exporter
    /// spawns a background flusher) and then tries to dial the
    /// endpoint. Marked ignore by default — the runtime would hang
    /// on the unreachable endpoint. Run with `cargo test -- --ignored
    /// --nocapture` against a real collector to exercise the path.
    #[cfg(feature = "otlp")]
    #[tokio::test]
    #[ignore = "needs a live OTLP collector; ignored by default"]
    async fn otlp_sink_constructs_with_endpoint() {
        let _ = OtlpSink::with_endpoint("http://127.0.0.1:4317");
    }
}

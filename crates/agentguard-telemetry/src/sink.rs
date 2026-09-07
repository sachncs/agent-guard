//! Sink trait and event payload.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Errors raised by [`Sink::emit`].
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

/// Telemetry event emitted by agentguard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkEvent {
    /// Unique event id (UUID v4).
    pub id: Uuid,
    /// Event timestamp.
    pub timestamp: DateTime<Utc>,
    /// Discriminator.
    pub kind: SinkEventKind,
}

/// What the event represents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkEventKind {
    /// Authorization decision (allow or deny).
    Decision {
        effect: String,
        principal: String,
        action: String,
        resource: String,
        policies: Vec<String>,
        reasons: Vec<String>,
        duration_micros: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trace_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        span_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tenant_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject_id: Option<String>,
        #[serde(default)]
        cached: bool,
    },
    /// Delegation token minted.
    DelegationMint {
        issuer: String,
        subject: String,
        actions: Vec<String>,
        ttl_seconds: i64,
    },
    /// Delegation token verified.
    DelegationVerify {
        success: bool,
        issuer: Option<String>,
        subject: Option<String>,
    },
    /// Policy bundle loaded or reloaded.
    PolicyReload {
        version: String,
        policy_count: usize,
        source: String,
    },
    /// Decision cache hit/miss.
    CacheLookup {
        hit: bool,
        principal: String,
        action: String,
    },
    /// Authorization failed because the PDP could not be reached.
    PdpError { error: String, fallback: String },
}

impl SinkEvent {
    pub fn decision(
        effect: impl Into<String>,
        principal: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        policies: Vec<String>,
        reasons: Vec<String>,
        duration_micros: u64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            kind: SinkEventKind::Decision {
                effect: effect.into(),
                principal: principal.into(),
                action: action.into(),
                resource: resource.into(),
                policies,
                reasons,
                duration_micros,
                trace_id: None,
                span_id: None,
                tenant_id: None,
                subject_id: None,
                cached: false,
            },
        }
    }

    pub fn with_trace(mut self, trace_id: String, span_id: String) -> Self {
        if let SinkEventKind::Decision {
            trace_id: ref mut t,
            span_id: ref mut s,
            ..
        } = self.kind
        {
            *t = Some(trace_id);
            *s = Some(span_id);
        }
        self
    }

    pub fn with_tenant(mut self, tenant_id: String, subject_id: Option<String>) -> Self {
        if let SinkEventKind::Decision {
            tenant_id: ref mut t,
            subject_id: ref mut s,
            ..
        } = self.kind
        {
            *t = Some(tenant_id);
            *s = subject_id;
        }
        self
    }

    pub fn mark_cached(mut self) -> Self {
        if let SinkEventKind::Decision {
            cached: ref mut c, ..
        } = self.kind
        {
            *c = true;
        }
        self
    }
}

/// Sink for telemetry events.
///
/// Implementations should be cheap to clone (typically `Arc<Sink>`) and
/// must be safe to call from multiple threads concurrently.
///
/// # Why `async_trait`
/// Rust's native `async fn` in traits doesn't support `dyn Sink`
/// without `BoxFuture` wrappers, and adding the bound requires
/// lifetime gymnastics at every call site. The `async_trait` macro
/// gives object safety for the cost of one `Box<dyn Future>` per
/// call. The Sink trait is consumed in only a handful of hot paths;
/// if/when those migrate to generics we can drop `async_trait`.
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

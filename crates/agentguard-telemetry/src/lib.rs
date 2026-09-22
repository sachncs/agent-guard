//! Pluggable observability layer for agentguard.
//!
//! [`Sink`] implementations provide JSONL and stdout event outputs, while
//! [`Metrics`] exposes the in-process counters and histograms used by the
//! server's Prometheus endpoint. The audit record chain is owned by the core
//! decision-log implementation.

pub mod metrics;
pub mod sink;
pub mod sinks;

pub use metrics::{Counter, Gauge, Histogram, Metrics, MetricsSnapshot};
pub use sink::{Sink, SinkError, SinkEvent, SinkEventKind};
pub use sinks::{jsonl::JsonlSink, stdout::StdoutSink};

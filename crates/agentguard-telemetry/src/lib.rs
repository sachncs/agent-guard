//! Pluggable observability layer for agentguard.
//!
//! See `stages/STAGE-1-telemetry.md` for the implementation plan and
//! `stages/STAGE-2-decision-log-hash-chain.md` for the tamper-evident
//! audit log that this crate's [`JsonlSink`] integrates with.

#![allow(clippy::needless_lifetimes)] // trait objects simplify the API

pub mod metrics;
pub mod sink;
pub mod sinks;

pub use metrics::{Counter, Gauge, Histogram, Metrics, MetricsSnapshot};
pub use sink::{Sink, SinkError, SinkEvent, SinkEventKind};
pub use sinks::{jsonl::JsonlSink, stdout::StdoutSink};

//! Observability support: trace context propagation + (future) metrics.

pub mod span;
pub use span::{SpanId, TraceContext, TraceId};

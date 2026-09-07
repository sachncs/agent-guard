//! Built-in sink implementations.

pub mod jsonl;
pub mod stdout;

#[cfg(feature = "otlp")]
pub mod otlp;

//! Pluggable observability layer for agentguard.
//!
//! See `stages/STAGE-1-telemetry.md` for the implementation plan.

#![allow(dead_code, unused_imports)] // stage-1 in progress

pub mod sink;

pub use sink::{Sink, SinkError, SinkEvent};
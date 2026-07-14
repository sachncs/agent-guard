//! Append-only structured decision log.
//!
//! See [`DecisionLog`] for the writer and [`DecisionRecord`] for the record
//! schema. The v2 record schema carries W3C trace context, tenant ID, and
//! subject ID for SAR queries. See `stages/STAGE-2-decision-log-hash-chain.md`
//! for the tamper-evident hash chain (added in Stage 2).

pub mod cache;
pub mod log;
pub mod record;

pub use cache::DecisionCache;
pub use log::DecisionLog;
pub use record::DecisionRecord;

//! Append-only structured decision log.
//!
//! See [`DecisionLog`] for the writer, [`DecisionRecord`] for the record
//! schema, and [`chain`] for the tamper-evident HMAC hash chain.

pub mod cache;
pub mod canonical;
pub mod chain;
pub mod formatter;
pub mod log;
pub mod record;

pub use cache::DecisionCache;
pub use chain::{ChainId, HashChain, HASH_LEN};
pub use formatter::{AuditFormatter, CefFormatter, EcsFormatter, JsonlFormatter, LeefFormatter};
pub use log::DecisionLog;
pub use record::DecisionRecord;

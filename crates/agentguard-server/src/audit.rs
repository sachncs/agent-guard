//! Audit persistence port used by PDP request handling.

use agentguard_core::decision::DecisionLog;
use agentguard_core::{Decision, Result};

/// Durable audit operations required by the HTTP and gRPC adapters.
///
/// Implementations must make `append_decision` durable before returning `Ok`.
/// The handler fails closed if appending fails. Calls run on the PDP's bounded
/// blocking-work pool, so a synchronous adapter may perform blocking I/O but
/// must not create its own unbounded queue. `is_chained` must only return true
/// when persisted records have tamper-evident integrity protection.
///
/// Embedders can inject an implementation with
/// [`AppState::with_audit_appender`](crate::authzen::AppState::with_audit_appender).
pub trait AuditAppender: Send + Sync {
    fn append_decision(&self, decision: &Decision) -> Result<()>;
    fn is_healthy(&self) -> bool;
    fn is_chained(&self) -> bool;
}

impl AuditAppender for DecisionLog {
    fn append_decision(&self, decision: &Decision) -> Result<()> {
        DecisionLog::append_decision(self, decision)
    }

    fn is_healthy(&self) -> bool {
        DecisionLog::is_healthy(self)
    }

    fn is_chained(&self) -> bool {
        DecisionLog::chain_id(self).is_some()
    }
}

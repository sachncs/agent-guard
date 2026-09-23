//! Audit persistence port used by PDP request handling.

use agentguard_core::decision::DecisionLog;
use agentguard_core::{Decision, Result};

/// Durable audit operations required by the HTTP and gRPC adapters.
///
/// Keeping the request handlers against this port lets tests and alternate
/// storage adapters exercise fail-closed behavior without depending on a
/// particular filesystem failure mode.
pub(crate) trait AuditAppender: Send + Sync {
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

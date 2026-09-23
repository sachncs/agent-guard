//! Audit persistence port used by PDP request handling.

use agentguard_core::decision::DecisionLog;
use agentguard_core::{Decision, Result};
use async_trait::async_trait;
use std::sync::Arc;

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

/// Async durable audit port for database or network-backed implementations.
///
/// Implementations must make `append_decision` durable before returning `Ok`.
/// Append is cancelled after the PDP's five-second deadline, so adapters must
/// make cancellation behavior explicit for their storage client; a timeout is
/// treated as an unknown/failed append and the decision is not returned.
/// Health and chain-integrity checks are awaited by `/readyz` with a bounded
/// timeout. As with the synchronous port, `is_chained` must only return true
/// when stored records are tamper-evident.
#[async_trait]
pub trait AsyncAuditAppender: Send + Sync {
    async fn append_decision(&self, decision: &Decision) -> Result<()>;
    async fn is_healthy(&self) -> bool;
    async fn is_chained(&self) -> bool;
}

#[derive(Clone)]
pub(crate) enum AuditWriter {
    Sync(Arc<dyn AuditAppender>),
    Async(Arc<dyn AsyncAuditAppender>),
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

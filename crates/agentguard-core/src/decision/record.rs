//! Decision record schema (v2).

use crate::authorize::Decision;
use crate::observability::{SpanId, TraceId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Structured record written for every authorization decision.
///
/// Old readers (v1) ignore all unknown fields, so adding fields is
/// backward-compatible at the JSON level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub effect: String,
    pub policies: Vec<String>,
    pub request_id: Option<String>,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub reasons: Vec<String>,
    pub session_id: Option<String>,
    pub agent_chain: Option<Vec<String>>,
    /// W3C Trace Context trace ID, propagated from the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<TraceId>,
    /// W3C Trace Context span ID, propagated from the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<SpanId>,
    /// Tenant ID for multi-tenant deployments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Subject ID for SAR queries (GDPR Art. 15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
}

impl DecisionRecord {
    pub fn from_decision(
        d: &Decision,
        session_id: Option<String>,
        agent_chain: Option<Vec<String>>,
    ) -> Self {
        let req = &d.request;
        let principal = req
            .get("principal")
            .and_then(|p| p.get("uid"))
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
            .or_else(|| req.get("principal").map(|p| p.to_string()))
            .unwrap_or_default();
        let action = req
            .get("action")
            .map(|a| {
                if let Some(tool) = a.get("tool").and_then(|t| t.as_str()) {
                    if let Some(op) = a.get("operation").and_then(|o| o.as_str()) {
                        format!("{}::{}", tool, op)
                    } else {
                        tool.to_string()
                    }
                } else {
                    a.to_string()
                }
            })
            .unwrap_or_default();
        let resource = req
            .get("resource")
            .and_then(|r| r.get("uid"))
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();

        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            effect: format!("{:?}", d.effect).to_lowercase(),
            policies: d.policies.clone(),
            request_id: req
                .get("request_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            principal,
            action,
            resource,
            reasons: d.reasons.clone(),
            session_id,
            agent_chain,
            trace_id: req
                .get("trace")
                .and_then(|t| t.get("trace_id"))
                .and_then(|s| s.as_str())
                .and_then(|s| s.parse().ok()),
            span_id: req
                .get("trace")
                .and_then(|t| t.get("span_id"))
                .and_then(|s| s.as_str())
                .and_then(|s| s.parse().ok()),
            tenant_id: req
                .get("tenant_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            subject_id: req
                .get("subject_id")
                .and_then(|v| v.as_str())
                .map(String::from),
        }
    }
}

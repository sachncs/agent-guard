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
    /// Authenticated PDP caller. This is server-added audit metadata and is
    /// intentionally separate from Cedar context and the evaluated principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_actor: Option<AuthenticatedActor>,
}

/// Provenance for a request accepted by a standalone authenticated PDP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthenticatedActor {
    pub subject_type: String,
    pub subject_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub credential_id: String,
    pub can_act_as: bool,
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
            id: Uuid::now_v7().to_string(),
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
            authenticated_actor: req
                .get("authenticated_actor")
                .cloned()
                .and_then(|actor| serde_json::from_value(actor).ok()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorize::Effect;

    #[test]
    fn decision_record_preserves_authenticated_caller_provenance() {
        let decision = Decision {
            effect: Effect::Allow,
            policies: vec!["policy0".into()],
            reasons: vec![],
            request: serde_json::json!({
                "principal":{"uid":"research-agent"},
                "authenticated_actor":{
                    "subject_type":"Agent",
                    "subject_id":"console-service",
                    "tenant_id":"tenant-a",
                    "credential_id":"key-123",
                    "can_act_as":true
                }
            }),
            trace: None,
            from_cache: false,
        };

        let record = DecisionRecord::from_decision(&decision, None, None);
        assert_eq!(record.principal, "research-agent");
        assert_eq!(
            record.authenticated_actor,
            Some(AuthenticatedActor {
                subject_type: "Agent".into(),
                subject_id: "console-service".into(),
                tenant_id: Some("tenant-a".into()),
                credential_id: "key-123".into(),
                can_act_as: true,
            })
        );
    }

    #[test]
    fn older_decision_record_json_without_actor_remains_compatible() {
        let value = serde_json::json!({
            "id":"legacy",
            "timestamp":"2025-01-01T00:00:00Z",
            "effect":"allow",
            "policies":[],
            "request_id":null,
            "principal":"alice",
            "action":"read",
            "resource":"doc",
            "reasons":[],
            "session_id":null,
            "agent_chain":null
        });
        let record: DecisionRecord = serde_json::from_value(value).unwrap();
        assert_eq!(record.authenticated_actor, None);
    }
}

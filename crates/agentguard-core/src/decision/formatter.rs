//! Audit log formatters for SIEM ingestion.
//!
//! Four formats are supported:
//! - `Jsonl` (default): pass-through JSON
//! - `Cef`: ArcSight Common Event Format
//! - `Leef`: IBM QRadar Log Event Extended Format
//! - `Ecs`: Elastic Common Schema (JSON)
//!
//! The trait has been replaced by an enum (`AuditFormat`) + a single
//! inherent `format()` method. This avoids the per-record `Box<dyn>`
//! indirection in the CLI's export path and lets the compiler inline
//! the format selection.

use crate::decision::record::DecisionRecord;
use serde::Serialize;
use std::str::FromStr;

/// Stable identifier for an audit format (e.g. `"jsonl"`, `"cef"`).
///
/// Used by the CLI's `--log-format` flag and the `AgentAuditFormat` HTTP
/// field (when added in a future version).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuditFormat {
    /// Pass-through JSON, one record per line.
    Jsonl,
    /// ArcSight Common Event Format.
    Cef,
    /// IBM QRadar Log Event Extended Format.
    Leef,
    /// Elastic Common Schema (JSON).
    Ecs,
}

impl AuditFormat {
    /// Stable lowercase string identifier for this format.
    pub fn name(self) -> &'static str {
        match self {
            AuditFormat::Jsonl => "jsonl",
            AuditFormat::Cef => "cef",
            AuditFormat::Leef => "leef",
            AuditFormat::Ecs => "ecs",
        }
    }

    /// Format one record into the appropriate line(s).
    pub fn format(self, rec: &DecisionRecord) -> String {
        match self {
            AuditFormat::Jsonl => serde_json::to_string(rec).unwrap_or_default(),
            AuditFormat::Cef => format_cef(rec),
            AuditFormat::Leef => format_leef(rec),
            AuditFormat::Ecs => format_ecs(rec),
        }
    }
}

impl FromStr for AuditFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "jsonl" => Ok(AuditFormat::Jsonl),
            "cef" => Ok(AuditFormat::Cef),
            "leef" => Ok(AuditFormat::Leef),
            "ecs" => Ok(AuditFormat::Ecs),
            other => Err(format!(
                "unknown audit format: {other} (use jsonl|cef|leef|ecs)"
            )),
        }
    }
}

impl std::fmt::Display for AuditFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

fn format_cef(rec: &DecisionRecord) -> String {
    let severity = if rec.effect == "allow" { 1 } else { 5 };
    let extensions = format!(
        "src={} suser={} act={} outcome={} cs1={} cs1Label=agentguardDecision cs2={} cs2Label=agentguardPolicy cs3={} cs3Label=agentguardResource",
        escape(rec.principal.as_str()),
        escape(rec.principal.as_str()),
        escape(&rec.action),
        if rec.effect == "allow" { "Success" } else { "Failure" },
        escape(&rec.effect),
        escape(&rec.policies.join(",")),
        escape(&rec.resource),
    );
    format!(
        "CEF:0|agentguard|agentguard|2.0|0|authz_decision|{}|{}",
        severity, extensions
    )
}

fn format_leef(rec: &DecisionRecord) -> String {
    let mut s = format!(
        "LEEF:2.0|agentguard|agentguard|2.0|authz_decision|\
         devTime={} usrName={} action={} outcome={} src={}",
        rec.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
        escape(&rec.principal),
        escape(&rec.action),
        if rec.effect == "allow" {
            "Success"
        } else {
            "Failure"
        },
        escape(&rec.resource),
    );
    if !rec.policies.is_empty() {
        s.push_str(&format!(
            " agentguardPolicy={}",
            escape(&rec.policies.join(","))
        ));
    }
    if let Some(t) = &rec.trace_id {
        s.push_str(&format!(" traceId={}", escape(&t.to_string())));
    }
    s
}

#[derive(Serialize)]
struct EcsRecord<'a> {
    #[serde(rename = "@timestamp")]
    timestamp: String,
    #[serde(rename = "event.action")]
    event_action: &'a str,
    #[serde(rename = "event.outcome")]
    outcome: &'a str,
    #[serde(rename = "event.kind")]
    kind: &'a str,
    #[serde(rename = "event.category")]
    category: &'a str,
    #[serde(rename = "user.name")]
    user_name: &'a str,
    #[serde(rename = "labels.agentguard_principal")]
    principal: &'a str,
    #[serde(rename = "labels.agentguard_action")]
    agent_action: &'a str,
    #[serde(rename = "labels.agentguard_resource")]
    resource: &'a str,
    #[serde(rename = "labels.agentguard_policies")]
    policies: String,
    #[serde(
        rename = "labels.agentguard_decision_id",
        skip_serializing_if = "Option::is_none"
    )]
    decision_id: Option<&'a str>,
    #[serde(
        rename = "labels.agentguard_trace_id",
        skip_serializing_if = "Option::is_none"
    )]
    trace_id: Option<String>,
}

fn format_ecs(rec: &DecisionRecord) -> String {
    let r = EcsRecord {
        timestamp: rec.timestamp.to_rfc3339(),
        event_action: "authz_decision",
        outcome: if rec.effect == "allow" {
            "success"
        } else {
            "failure"
        },
        kind: "event",
        category: "authentication",
        user_name: &rec.principal,
        principal: &rec.principal,
        agent_action: &rec.action,
        resource: &rec.resource,
        policies: rec.policies.join(","),
        decision_id: Some(&rec.id),
        trace_id: rec.trace_id.as_ref().map(|t| t.to_string()),
    };
    serde_json::to_string(&r).unwrap_or_default()
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn fixture() -> DecisionRecord {
        DecisionRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            effect: "allow".into(),
            policies: vec!["policy0".into()],
            request_id: None,
            principal: "alice".into(),
            action: "send_email".into(),
            resource: "alice@acme".into(),
            reasons: vec![],
            session_id: None,
            agent_chain: None,
            trace_id: None,
            span_id: None,
            tenant_id: None,
            subject_id: None,
        }
    }

    #[test]
    fn jsonl_format_round_trips() {
        let line = AuditFormat::Jsonl.format(&fixture());
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["principal"], "alice");
    }

    #[test]
    fn cef_includes_required_fields() {
        let line = AuditFormat::Cef.format(&fixture());
        assert!(line.starts_with("CEF:0|agentguard|agentguard|"));
        assert!(line.contains("suser=alice") || line.contains("suser\\=alice"));
        assert!(line.contains("outcome=Success") || line.contains("outcome\\=Success"));
    }

    #[test]
    fn leef_format_starts_correctly() {
        let line = AuditFormat::Leef.format(&fixture());
        assert!(line.starts_with("LEEF:2.0|agentguard|"));
        assert!(line.contains("usrName=alice"));
    }

    #[test]
    fn ecs_emits_required_fields() {
        let line = AuditFormat::Ecs.format(&fixture());
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["event.action"], "authz_decision");
        assert_eq!(parsed["event.outcome"], "success");
        assert_eq!(parsed["user.name"], "alice");
        assert_eq!(parsed["labels.agentguard_principal"], "alice");
    }

    #[test]
    fn format_from_str_round_trips() {
        for name in ["jsonl", "cef", "leef", "ecs"] {
            let f: AuditFormat = name.parse().unwrap();
            assert_eq!(f.name(), name);
        }
    }

    #[test]
    fn unknown_format_errors() {
        assert!("xml".parse::<AuditFormat>().is_err());
    }
}
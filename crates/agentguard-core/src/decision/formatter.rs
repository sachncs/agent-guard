//! Audit log formatters for SIEM ingestion.
//!
//! - [`JsonlFormatter`]: pass-through (default)
//! - [`CefFormatter`]: ArcSight Common Event Format
//! - [`LeefFormatter`]: IBM QRadar Log Event Extended Format
//! - [`EcsFormatter`]: Elastic Common Schema

use crate::decision::record::DecisionRecord;
use serde::Serialize;

/// Trait implemented by all audit formatters.
pub trait AuditFormatter: Send + Sync {
    /// Stable identifier for this format (e.g. `"jsonl"`, `"cef"`).
    fn name(&self) -> &str;

    /// Convert one record into the formatted line(s).
    fn format(&self, rec: &DecisionRecord) -> String;
}

/// Pass-through JSON formatter (the default — used by the CLI when
/// `--log-format jsonl`).
pub struct JsonlFormatter;

impl AuditFormatter for JsonlFormatter {
    fn name(&self) -> &str {
        "jsonl"
    }

    fn format(&self, rec: &DecisionRecord) -> String {
        serde_json::to_string(rec).unwrap_or_default()
    }
}

/// ArcSight Common Event Format.
///
/// Format: `CEF:Version|Vendor|Product|Version|EventID|Name|Severity|Extension`
#[derive(Debug, Clone, Default)]
pub struct CefFormatter;

impl AuditFormatter for CefFormatter {
    fn name(&self) -> &str {
        "cef"
    }

    fn format(&self, rec: &DecisionRecord) -> String {
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
}

/// IBM QRadar Log Event Extended Format.
///
/// Format: `LEEF:2.0|Vendor|Product|Version|EventID|...`
#[derive(Debug, Clone, Default)]
pub struct LeefFormatter;

impl AuditFormatter for LeefFormatter {
    fn name(&self) -> &str {
        "leef"
    }

    fn format(&self, rec: &DecisionRecord) -> String {
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
}

/// Elastic Common Schema (JSON).
#[derive(Debug, Clone, Default)]
pub struct EcsFormatter;

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

impl AuditFormatter for EcsFormatter {
    fn name(&self) -> &str {
        "ecs"
    }

    fn format(&self, rec: &DecisionRecord) -> String {
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
    fn cef_includes_required_fields() {
        let line = CefFormatter.format(&fixture());
        assert!(line.starts_with("CEF:0|agentguard|agentguard|"));
        // CEF escapes `=` to `\=`. Verify either form.
        assert!(line.contains("suser=alice") || line.contains("suser\\=alice"));
        assert!(line.contains("outcome=Success") || line.contains("outcome\\=Success"));
    }

    #[test]
    fn leef_format_starts_correctly() {
        let line = LeefFormatter.format(&fixture());
        assert!(line.starts_with("LEEF:2.0|agentguard|"));
        assert!(line.contains("usrName=alice"));
    }

    #[test]
    fn ecs_emits_required_fields() {
        let line = EcsFormatter.format(&fixture());
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["event.action"], "authz_decision");
        assert_eq!(parsed["event.outcome"], "success");
        assert_eq!(parsed["user.name"], "alice");
        assert_eq!(parsed["labels.agentguard_principal"], "alice");
    }
}

//! Agent actions: tool calls, optionally with an operation.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A tool-call action: e.g. `send_email`, or `s3::PutObject`.
///
/// Cedar action UID format: `Action::"ToolCall::<tool>"` or
/// `Action::"ToolCall::<tool>::<operation>"`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct AgentAction {
    /// Tool name (e.g. `send_email`, `s3`, `repo_read`).
    pub tool: String,
    /// Optional operation within the tool (e.g. `PutObject` for `s3`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
}

impl AgentAction {
    /// Construct an action for a whole-tool call (no specific operation).
    pub fn tool(name: impl Into<String>) -> Self {
        Self {
            tool: name.into(),
            operation: None,
        }
    }

    /// Construct an action for a specific operation within a tool.
    pub fn tool_op(name: impl Into<String>, op: impl Into<String>) -> Self {
        Self {
            tool: name.into(),
            operation: Some(op.into()),
        }
    }

    /// Cedar action UID like `Action::"ToolCall::send_email"`.
    #[deprecated(
        since = "0.2.1",
        note = "Use the Display impl to write into an existing buffer (no allocation)."
    )]
    pub fn action_uid(&self) -> String {
        match &self.operation {
            Some(op) => format!("Action::\"ToolCall::{}::{}\"", self.tool, op),
            None => format!("Action::\"ToolCall::{}\"", self.tool),
        }
    }

    /// Just the ID portion (without the `Action::` namespace).
    pub fn action_id(&self) -> String {
        match &self.operation {
            Some(op) => format!("ToolCall::{}::{}", self.tool, op),
            None => format!("ToolCall::{}", self.tool),
        }
    }
}

impl fmt::Display for AgentAction {
    /// Writes the Cedar action UID into the formatter without allocating
    /// a `String`. Equivalent to the deprecated `action_uid()` but
    /// allocation-free.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.operation {
            Some(op) => write!(f, "Action::\"ToolCall::{}::{}\"", self.tool, op),
            None => write!(f, "Action::\"ToolCall::{}\"", self.tool),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_action_uid() {
        let a = AgentAction::tool("send_email");
        assert_eq!(format!("{}", a), "Action::\"ToolCall::send_email\"");
        assert_eq!(a.action_id(), "ToolCall::send_email");
    }

    #[test]
    fn tool_op_action_uid() {
        let a = AgentAction::tool_op("s3", "PutObject");
        assert_eq!(format!("{}", a), "Action::\"ToolCall::s3::PutObject\"");
        assert_eq!(a.action_id(), "ToolCall::s3::PutObject");
    }

    #[test]
    fn action_without_operation_omits_double_colon() {
        let a = AgentAction::tool("search");
        // Single-tool action: no `::op` segment in the action id.
        assert_eq!(a.action_id(), "ToolCall::search");
        assert!(!a.action_id().contains("::ToolCall::"));
    }

    #[test]
    fn action_serde_round_trip() {
        let a = AgentAction::tool_op("email", "send");
        let json = serde_json::to_string(&a).unwrap();
        let parsed: AgentAction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, a);
    }

    #[test]
    fn action_without_operation_serializes_no_op_field() {
        let a = AgentAction::tool("solo");
        let json = serde_json::to_value(&a).unwrap();
        // The `operation` field has `skip_serializing_if = "Option::is_none"`,
        // so it should not appear in the serialized form.
        assert!(json.get("operation").is_none());
    }
}

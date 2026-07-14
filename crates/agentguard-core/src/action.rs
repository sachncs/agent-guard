//! Agent actions: tool calls, optionally with an operation.

use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_action_uid() {
        let a = AgentAction::tool("send_email");
        assert_eq!(a.action_uid(), "Action::\"ToolCall::send_email\"");
        assert_eq!(a.action_id(), "ToolCall::send_email");
    }

    #[test]
    fn tool_op_action_uid() {
        let a = AgentAction::tool_op("s3", "PutObject");
        assert_eq!(a.action_uid(), "Action::\"ToolCall::s3::PutObject\"");
        assert_eq!(a.action_id(), "ToolCall::s3::PutObject");
    }
}

//! Build Cedar requests from agent concepts: tools, callers, sub-agents.

use crate::error::{Error, Result};
use cedar_policy::{Context, EntityId, EntityTypeName, EntityUid, Request};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Principal {
    User {
        uid: String,
        #[serde(default)]
        attrs: IndexMap<String, serde_json::Value>,
    },
    Agent {
        uid: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_uid: Option<String>,
        #[serde(default)]
        attrs: IndexMap<String, serde_json::Value>,
    },
}

impl Principal {
    pub fn user(uid: impl Into<String>) -> Self {
        Principal::User {
            uid: uid.into(),
            attrs: IndexMap::new(),
        }
    }

    pub fn agent(uid: impl Into<String>) -> Self {
        Principal::Agent {
            uid: uid.into(),
            parent_uid: None,
            attrs: IndexMap::new(),
        }
    }

    pub fn subagent(uid: impl Into<String>, parent: impl Into<String>) -> Self {
        Principal::Agent {
            uid: uid.into(),
            parent_uid: Some(parent.into()),
            attrs: IndexMap::new(),
        }
    }

    pub fn with_attr(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self {
        let map = match &mut self {
            Principal::User { attrs, .. } => attrs,
            Principal::Agent { attrs, .. } => attrs,
        };
        map.insert(k.into(), v.into());
        self
    }

    pub fn entity_type(&self) -> &'static str {
        match self {
            Principal::User { .. } => "User",
            Principal::Agent { .. } => "Agent",
        }
    }

    pub fn entity_uid(&self) -> String {
        format!("{}::\"{}\"", self.entity_type(), self.id())
    }

    pub fn id(&self) -> &str {
        match self {
            Principal::User { uid, .. } | Principal::Agent { uid, .. } => uid,
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.entity_uid())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resource {
    pub entity_type: String,
    pub uid: String,
    #[serde(default)]
    pub attrs: IndexMap<String, serde_json::Value>,
}

impl Resource {
    pub fn new(entity_type: impl Into<String>, uid: impl Into<String>) -> Self {
        Self {
            entity_type: entity_type.into(),
            uid: uid.into(),
            attrs: IndexMap::new(),
        }
    }

    pub fn with_attr(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self {
        self.attrs.insert(k.into(), v.into());
        self
    }

    pub fn entity_uid(&self) -> String {
        format!("{}::\"{}\"", self.entity_type, self.uid)
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.entity_uid())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentAction {
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
}

impl AgentAction {
    pub fn tool(name: impl Into<String>) -> Self {
        Self {
            tool: name.into(),
            operation: None,
        }
    }

    pub fn tool_op(name: impl Into<String>, op: impl Into<String>) -> Self {
        Self {
            tool: name.into(),
            operation: Some(op.into()),
        }
    }

    pub fn action_uid(&self) -> String {
        match &self.operation {
            Some(op) => format!("Action::\"ToolCall::{}::{}\"", self.tool, op),
            None => format!("Action::\"ToolCall::{}\"", self.tool),
        }
    }

    pub fn action_id(&self) -> String {
        match &self.operation {
            Some(op) => format!("ToolCall::{}::{}", self.tool, op),
            None => format!("ToolCall::{}", self.tool),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentContext {
    #[serde(default)]
    pub args: serde_json::Value,
    #[serde(default)]
    pub session: IndexMap<String, serde_json::Value>,
}

impl AgentContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_arg(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self {
        if !self.args.is_object() {
            self.args = serde_json::json!({});
        }
        self.args
            .as_object_mut()
            .unwrap()
            .insert(k.into(), v.into());
        self
    }

    pub fn with_session(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self {
        self.session.insert(k.into(), v.into());
        self
    }

    /// Serialize to a JSON object suitable for `Context::from_json_str`.
    /// Args are flattened into the top-level context so they match the
    /// action's declared schema fields. Session metadata is grouped under
    /// a `session` record so it doesn't collide with action-specific fields.
    pub fn to_json_object(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut map = serde_json::Map::new();
        if let serde_json::Value::Object(args) = &self.args {
            for (k, v) in args {
                map.insert(k.clone(), v.clone());
            }
        }
        if !self.session.is_empty() {
            let session_map: serde_json::Map<_, _> = self
                .session
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            map.insert("session".into(), serde_json::Value::Object(session_map));
        }
        map
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRequest {
    pub principal: Principal,
    pub action: AgentAction,
    pub resource: Resource,
    pub context: AgentContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl AgentRequest {
    pub fn new(
        principal: Principal,
        action: AgentAction,
        resource: Resource,
        context: AgentContext,
    ) -> Self {
        Self {
            principal,
            action,
            resource,
            context,
            request_id: None,
        }
    }

    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Convert to a `cedar_policy::Request`. `schema` is used to construct
    /// a typed context (validates context shape per action) when available.
    pub fn to_cedar_request(&self, schema: Option<&cedar_policy::Schema>) -> Result<Request> {
        let principal_eid = EntityId::new(self.principal.id());
        let principal_etype =
            EntityTypeName::from_str(self.principal.entity_type()).map_err(|e| {
                Error::InvalidPrincipal(format!("{}: {}", self.principal.entity_type(), e))
            })?;
        let principal_uid = EntityUid::from_type_name_and_id(principal_etype, principal_eid);

        let action_eid = EntityId::new(self.action.action_id());
        let action_etype = EntityTypeName::from_str("Action")
            .map_err(|e| Error::InvalidPrincipal(format!("Action: {}", e)))?;
        let action_uid = EntityUid::from_type_name_and_id(action_etype, action_eid);

        let resource_eid = EntityId::new(&self.resource.uid);
        let resource_etype = EntityTypeName::from_str(&self.resource.entity_type)
            .map_err(|e| Error::InvalidResource(format!("{}: {}", self.resource.entity_type, e)))?;
        let resource_uid = EntityUid::from_type_name_and_id(resource_etype, resource_eid);

        // Build context JSON.
        let mut ctx_map = self.context.to_json_object();
        let ctx_json = serde_json::Value::Object(std::mem::take(&mut ctx_map));

        let context = match schema {
            Some(s) => {
                let json_str = serde_json::to_string(&ctx_json)?;
                Context::from_json_str(&json_str, Some((s, &action_uid)))
                    .map_err(|e| Error::InvalidContext(e.to_string()))?
            }
            None => Context::from_json_str(&serde_json::to_string(&ctx_json)?, None)
                .map_err(|e| Error::InvalidContext(e.to_string()))?,
        };

        let req = Request::new(principal_uid, action_uid, resource_uid, context, schema)
            .map_err(|e| Error::InvalidContext(e.to_string()))?;

        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_principal() {
        let p = Principal::user("alice").with_attr("role", "admin");
        assert_eq!(p.entity_type(), "User");
        assert_eq!(p.entity_uid(), "User::\"alice\"");
    }

    #[test]
    fn test_agent_with_parent() {
        let p = Principal::subagent("summarizer", "research");
        assert_eq!(p.entity_type(), "Agent");
        assert_eq!(p.entity_uid(), "Agent::\"summarizer\"");
    }

    #[test]
    fn test_action_uid() {
        let a = AgentAction::tool("send_email");
        assert_eq!(a.action_uid(), "Action::\"ToolCall::send_email\"");
        let a = AgentAction::tool_op("s3", "PutObject");
        assert_eq!(a.action_uid(), "Action::\"ToolCall::s3::PutObject\"");
    }

    #[test]
    fn test_context_builder() {
        let c = AgentContext::new()
            .with_arg("to", "[email protected]")
            .with_session("ip", "10.0.0.1");
        assert_eq!(c.args["to"], "[email protected]");
        assert_eq!(c.session["ip"], "10.0.0.1");
    }
}

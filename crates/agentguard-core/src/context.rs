//! Request context: tool arguments plus session metadata.
//!
//! Tool args are flattened into the top-level context for schema validation;
//! session metadata is grouped under a `session` record to avoid colliding
//! with action-specific fields.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Structured context for an agent request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentContext {
    /// Tool arguments as a JSON object. Flattened to top level on serialization.
    #[serde(default)]
    pub args: serde_json::Value,
    /// Free-form session metadata: `ip`, `user_agent`, `mfa`, `ts`, etc.
    #[serde(default)]
    pub session: IndexMap<String, serde_json::Value>,
}

impl AgentContext {
    /// Construct an empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a tool argument and return `self` for chaining.
    pub fn with_arg(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self {
        if !self.args.is_object() {
            self.args = serde_json::json!({});
        }
        self.args
            .as_object_mut()
            .expect("just initialized to object")
            .insert(k.into(), v.into());
        self
    }

    /// Add a session metadata field and return `self` for chaining.
    pub fn with_session(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self {
        self.session.insert(k.into(), v.into());
        self
    }

    /// Serialize to a JSON object suitable for `Context::from_json_str`.
    ///
    /// Args are flattened into the top-level so they match the action's
    /// declared schema fields. Session metadata is grouped under a
    /// `session` record so it doesn't collide with action-specific fields.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_appends_args_and_session() {
        let c = AgentContext::new()
            .with_arg("to", "[email protected]")
            .with_session("ip", "10.0.0.1");
        assert_eq!(c.args["to"], "[email protected]");
        assert_eq!(c.session["ip"], "10.0.0.1");
    }

    #[test]
    fn to_json_object_flattens_args() {
        let c = AgentContext::new()
            .with_arg("amount", 1000)
            .with_session("mfa", true);
        let obj = c.to_json_object();
        assert_eq!(obj["amount"], 1000);
        assert!(obj.contains_key("session"));
    }
}

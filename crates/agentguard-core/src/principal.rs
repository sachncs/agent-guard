//! Principals in agentguard: human `User`s and AI `Agent`s.
//!
//! Agents may have a parent (for sub-agent delegation chains): a `summarizer`
//! agent's parent might be a `research` agent, whose parent is a `User`.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::ids::PrincipalId;

/// A principal is either a `User` (human) or an `Agent` (AI). Both become
/// Cedar entities of type `User` or `Agent`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Principal {
    /// A human user.
    User {
        uid: PrincipalId,
        #[serde(default)]
        attrs: IndexMap<String, serde_json::Value>,
    },
    /// An AI agent, optionally with a parent (sub-agent pattern).
    Agent {
        uid: PrincipalId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_uid: Option<PrincipalId>,
        #[serde(default)]
        attrs: IndexMap<String, serde_json::Value>,
    },
}

impl Principal {
    /// Construct a `User` principal with the given UID.
    pub fn user(uid: impl Into<PrincipalId>) -> Self {
        Principal::User {
            uid: uid.into(),
            attrs: IndexMap::new(),
        }
    }

    /// Construct an `Agent` principal with the given UID and no parent.
    pub fn agent(uid: impl Into<PrincipalId>) -> Self {
        Principal::Agent {
            uid: uid.into(),
            parent_uid: None,
            attrs: IndexMap::new(),
        }
    }

    /// Construct a sub-agent whose parent is another agent.
    pub fn subagent(uid: impl Into<PrincipalId>, parent: impl Into<PrincipalId>) -> Self {
        Principal::Agent {
            uid: uid.into(),
            parent_uid: Some(parent.into()),
            attrs: IndexMap::new(),
        }
    }

    /// Add an attribute and return `self` for chaining.
    pub fn with_attr(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self {
        let map = match &mut self {
            Principal::User { attrs, .. } => attrs,
            Principal::Agent { attrs, .. } => attrs,
        };
        map.insert(k.into(), v.into());
        self
    }

    /// Cedar entity type name (`User` or `Agent`).
    pub fn entity_type(&self) -> &'static str {
        match self {
            Principal::User { .. } => "User",
            Principal::Agent { .. } => "Agent",
        }
    }

    /// Full Cedar entity UID like `User::"alice"`.
    pub fn entity_uid(&self) -> String {
        format!("{}::\"{}\"", self.entity_type(), self.id())
    }

    /// The principal's UID without the type prefix.
    pub fn id(&self) -> &PrincipalId {
        match self {
            Principal::User { uid, .. } | Principal::Agent { uid, .. } => uid,
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.entity_uid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_principal_entity_uid() {
        let p = Principal::user("alice").with_attr("role", "admin");
        assert_eq!(p.entity_type(), "User");
        assert_eq!(p.entity_uid(), "User::\"alice\"");
    }

    #[test]
    fn subagent_has_parent() {
        let p = Principal::subagent("summarizer", "research");
        assert_eq!(p.entity_type(), "Agent");
        assert_eq!(p.entity_uid(), "Agent::\"summarizer\"");
        assert_eq!(p.id(), &PrincipalId::from("summarizer"));
    }
}

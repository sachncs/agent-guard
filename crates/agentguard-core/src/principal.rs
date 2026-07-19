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
///
/// # Construction
/// Use [`Principal::user`], [`Principal::agent`], [`Principal::subagent`],
/// or [`Principal::with_attr`] — never construct the enum variants
/// directly. The variant fields are public only because `serde`
/// deserializes into them; treating them as a stable public API is
/// unsupported. `#[non_exhaustive]` keeps external matches safe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Principal {
    /// A human user.
    ///
    /// Invariant: `parent_uid` is meaningless here; Cedar policies
    /// should not branch on a `User`'s parent.
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
    ///
    /// # Examples
    ///
    /// ```
    /// use agentguard_core::Principal;
    /// let p = Principal::user("alice");
    /// assert_eq!(p.entity_uid(), "User::\"alice\"");
    /// ```
    pub fn user(uid: impl Into<PrincipalId>) -> Self {
        Principal::User {
            uid: uid.into(),
            attrs: IndexMap::new(),
        }
    }

    /// Construct an `Agent` principal with the given UID and no parent.
    ///
    /// # Examples
    ///
    /// ```
    /// use agentguard_core::Principal;
    /// let p = Principal::agent("email-bot");
    /// assert_eq!(p.entity_type(), "Agent");
    /// ```
    pub fn agent(uid: impl Into<PrincipalId>) -> Self {
        Principal::Agent {
            uid: uid.into(),
            parent_uid: None,
            attrs: IndexMap::new(),
        }
    }

    /// Construct a sub-agent whose parent is another agent.
    ///
    /// # Examples
    ///
    /// ```
    /// use agentguard_core::Principal;
    /// let p = Principal::subagent("summarizer", "research");
    /// assert_eq!(p.entity_uid(), "Agent::\"summarizer\"");
    /// ```
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
    ///
    /// Prefer the [`Display`](std::fmt::Display) impl for formatting into
    /// an existing buffer (avoids a `String` allocation on the hot path).
    /// This method is retained for callers that genuinely need an owned
    /// `String` (e.g. serialization to JSON via `serde_json::json!`).
    #[deprecated(
        since = "0.2.1",
        note = "Use the Display impl to write into an existing buffer (no allocation)."
    )]
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
        write!(f, "{}::\"{}\"", self.entity_type(), self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_principal_entity_uid() {
        let p = Principal::user("alice").with_attr("role", "admin");
        assert_eq!(p.entity_type(), "User");
        assert_eq!(format!("{}", p), "User::\"alice\"");
    }

    #[test]
    fn subagent_has_parent() {
        let p = Principal::subagent("summarizer", "research");
        assert_eq!(p.entity_type(), "Agent");
        assert_eq!(format!("{}", p), "Agent::\"summarizer\"");
        assert_eq!(p.id(), &PrincipalId::from("summarizer"));
    }

    #[test]
    fn agent_no_parent_omits_parent_uid() {
        let p = Principal::agent("solo");
        assert_eq!(p.entity_type(), "Agent");
        assert_eq!(p.id(), &PrincipalId::from("solo"));
        // `parent_uid` is `skip_serializing_if = "Option::is_none"`, so a
        // parentless agent must not emit the field at all (avoids ambiguity
        // between `null` and absent on the deserializing side).
        let json = serde_json::to_value(&p).unwrap();
        assert!(
            json.get("parent_uid").is_none(),
            "parent_uid leaked: {json}"
        );
    }

    #[test]
    fn with_attr_supports_multiple_attrs() {
        let p = Principal::user("alice")
            .with_attr("role", "admin")
            .with_attr("tenant", "acme-corp")
            .with_attr("level", "5");
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["attrs"]["role"], "admin");
        assert_eq!(json["attrs"]["tenant"], "acme-corp");
        assert_eq!(json["attrs"]["level"], "5");
    }

    #[test]
    fn principal_serde_round_trips() {
        let p = Principal::subagent("research-bot", "admin");
        let json = serde_json::to_string(&p).unwrap();
        let parsed: Principal = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn user_and_agent_with_same_id_differ() {
        // Two principals with the same id but different variants are
        // not equal because their entity_type differs.
        let u = Principal::user("alice");
        let a = Principal::agent("alice");
        assert_ne!(u, a);
        assert_eq!(u.entity_type(), "User");
        assert_eq!(a.entity_type(), "Agent");
    }

    #[test]
    fn user_display_uses_entity_uid() {
        let p = Principal::user("alice");
        assert_eq!(format!("{}", p), "User::\"alice\"");
    }

    #[test]
    fn subagent_display_uses_entity_uid() {
        let p = Principal::subagent("summarizer", "research");
        assert_eq!(format!("{}", p), "Agent::\"summarizer\"");
    }
}

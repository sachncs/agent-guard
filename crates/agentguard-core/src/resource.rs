//! Resources acted on: any Cedar entity (Mailbox, Repository, Document, ...).

use crate::ids::ResourceId;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A resource being acted on. The `entity_type` is the Cedar type name
/// (`Mailbox`, `Repository`, etc) and `uid` is the entity's ID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct Resource {
    pub entity_type: String,
    pub uid: ResourceId,
    #[serde(default)]
    pub attrs: IndexMap<String, serde_json::Value>,
}

impl Resource {
    /// Construct a resource with no attributes.
    pub fn new(entity_type: impl Into<String>, uid: impl Into<ResourceId>) -> Self {
        Self {
            entity_type: entity_type.into(),
            uid: uid.into(),
            attrs: IndexMap::new(),
        }
    }

    /// Add an attribute and return `self` for chaining.
    pub fn with_attr(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self {
        self.attrs.insert(k.into(), v.into());
        self
    }

    /// Full Cedar entity UID like `Mailbox::"alice@acme"`.
    ///
    /// Prefer the [`Display`](std::fmt::Display) impl for formatting into
    /// an existing buffer (avoids a `String` allocation on the hot path).
    /// This method is retained for callers that genuinely need an owned
    /// `String` (e.g. serialization to JSON).
    #[deprecated(
        since = "0.2.1",
        note = "Use the Display impl to write into an existing buffer (no allocation)."
    )]
    pub fn entity_uid(&self) -> String {
        format!("{}::\"{}\"", self.entity_type, self.uid)
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::\"{}\"", self.entity_type, self.uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_entity_uid_uses_type_and_id() {
        let r = Resource::new("Mailbox", "alice@acme");
        assert_eq!(format!("{}", r), "Mailbox::\"alice@acme\"");
    }

    #[test]
    fn resource_display_matches_entity_uid() {
        let r = Resource::new("Document", "doc-1");
        assert_eq!(format!("{}", r), "Document::\"doc-1\"");
    }

    #[test]
    fn resource_serde_round_trip() {
        let r = Resource::new("Mailbox", "alice@acme");
        let json = serde_json::to_string(&r).unwrap();
        let parsed: Resource = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn resource_attrs_default_to_empty() {
        let r = Resource::new("Mailbox", "x");
        assert!(r.attrs.is_empty());
    }

    #[test]
    fn resource_uid_is_typed() {
        // The compile-time type prevents passing a PrincipalId where
        // a ResourceId is expected.
        let r = Resource::new("Mailbox", "alice@acme");
        let _uid: &ResourceId = &r.uid;
        // &str also works (ResourceId: From<&str>).
        let r2 = Resource::new("Mailbox", "alice@acme");
        assert_eq!(&*r2.uid, "alice@acme");
    }
}

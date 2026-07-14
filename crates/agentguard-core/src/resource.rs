//! Resources acted on: any Cedar entity (Mailbox, Repository, Document, ...).

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A resource being acted on. The `entity_type` is the Cedar type name
/// (`Mailbox`, `Repository`, etc) and `uid` is the entity's ID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct Resource {
    pub entity_type: String,
    pub uid: String,
    #[serde(default)]
    pub attrs: IndexMap<String, serde_json::Value>,
}

impl Resource {
    /// Construct a resource with no attributes.
    pub fn new(entity_type: impl Into<String>, uid: impl Into<String>) -> Self {
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
    pub fn entity_uid(&self) -> String {
        format!("{}::\"{}\"", self.entity_type, self.uid)
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.entity_uid())
    }
}

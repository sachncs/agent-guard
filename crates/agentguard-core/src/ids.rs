//! Typed wrappers for Cedar entity identifiers.
//!
//! Three separate types (`PrincipalId`, `ActionId`, `ResourceId`) prevent
//! accidentally passing a principal UID where an action UID is expected.
//! All wrap a `String` and deref to `str`.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

/// Identifier of a principal (User or Agent) entity.
///
/// Format: a string ID like `alice` (without the type prefix). Combined with
/// the entity type (`User::` or `Agent::`) it forms a Cedar entity UID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrincipalId(pub String);

impl PrincipalId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl Deref for PrincipalId {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: Into<String>> From<T> for PrincipalId {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

/// Identifier of an action entity — e.g. `ToolCall::send_email`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActionId(pub String);

impl ActionId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl Deref for ActionId {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: Into<String>> From<T> for ActionId {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

/// Identifier of a resource entity — e.g. a Mailbox or Repository.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ResourceId(pub String);

impl ResourceId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl Deref for ResourceId {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: Into<String>> From<T> for ResourceId {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_id_derefs_to_str() {
        let id: PrincipalId = "alice".into();
        assert_eq!(&*id, "alice");
        assert_eq!(format!("{}", id), "alice");
    }

    #[test]
    fn distinct_types_are_distinct() {
        let p: PrincipalId = "alice".into();
        let a: ActionId = "alice".into();
        let r: ResourceId = "alice".into();
        // All serialize identically, but are different types — preventing
        // accidental cross-type usage at compile time.
        assert_eq!(p.0, a.0);
        assert_eq!(a.0, r.0);
    }
}

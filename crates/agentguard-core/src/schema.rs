//! Schema utilities: parse + introspection using cedar-policy's structured
//! accessors.

use crate::error::{Error, Result};
use cedar_policy::Schema;
use serde::{Deserialize, Serialize};

/// A parsed schema, paired with its source text.
#[derive(Debug, Clone)]
pub struct SchemaParsed {
    pub schema: cedar_policy::Schema,
    pub source: String,
}

/// Parse a `cedarschema` source string into a `cedar_policy::Schema`.
pub fn parse_schema(src: &str) -> Result<cedar_policy::Schema> {
    let (s, _w) = cedar_policy::Schema::from_cedarschema_str(src)
        .map_err(|e| Error::Schema(e.to_string()))?;
    Ok(s)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityDef {
    pub name: String,
    pub kind: EntityKind,
    pub attributes: Vec<AttrDef>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Entity,
    Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttrDef {
    pub name: String,
    pub ty: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaSummary {
    pub entities: Vec<EntityDef>,
    pub actions: Vec<EntityDef>,
}

/// Build a [`SchemaSummary`] by walking cedar-policy's structured API.
pub fn describe(src: &str) -> Result<SchemaSummary> {
    let schema = parse_schema(src)?;
    Ok(build_summary(&schema))
}

fn build_summary(schema: &Schema) -> SchemaSummary {
    let mut entities = Vec::new();
    for et in schema.entity_types() {
        entities.push(entity_def(et));
    }
    let mut actions = Vec::new();
    for a in schema.actions() {
        actions.push(action_def(a));
    }
    SchemaSummary { entities, actions }
}

fn entity_def(et: &cedar_policy::EntityTypeName) -> EntityDef {
    // The cedar-policy public API exposes the entity type name; attribute
    // introspection goes through the AST-level ValidatorSchemaFragment which
    // is gated behind unstable features. We report the type with no
    // attributes here. Future work can extend this via the fragment API.
    EntityDef {
        name: et.to_string(),
        kind: EntityKind::Entity,
        attributes: vec![],
    }
}

fn action_def(a: &cedar_policy::EntityUid) -> EntityDef {
    // The cedar-policy public API exposes the action as an `EntityUid` like
    // `Action::"ToolCall::send_email"`. Surface only the action id portion
    // (matches the format Cedar uses in policy text).
    let raw = a.to_string();
    let name = raw
        .strip_prefix("Action::\"")
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(&raw)
        .to_string();
    EntityDef {
        name,
        kind: EntityKind::Action,
        attributes: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_extracts_entity_and_action_names() {
        let src = r#"
entity User;
entity Mailbox;
action "ToolCall::send_email" appliesTo { principal: [User], resource: [Mailbox] };
action "ToolCall::read_doc" appliesTo { principal: [User], resource: [Mailbox] };
"#;
        let s = describe(src).unwrap();
        let names: Vec<&str> = s.entities.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"User"));
        assert!(names.contains(&"Mailbox"));
        let actions: Vec<&str> = s.actions.iter().map(|a| a.name.as_str()).collect();
        assert!(actions.contains(&"ToolCall::send_email"));
        assert!(actions.contains(&"ToolCall::read_doc"));
    }

    #[test]
    fn describe_handles_malformed_schema() {
        // parse_schema is strict; malformed input should error rather than
        // silently producing empty results.
        let res = describe("not a valid schema");
        assert!(res.is_err());
    }
}

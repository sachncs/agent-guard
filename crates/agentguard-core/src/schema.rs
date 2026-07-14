//! Schema utilities: parse + simple textual introspection.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

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

/// Textual scan of a `cedarschema` source. Best-effort; covers the common
/// shapes produced by `agentguard init` and standard hand-written schemas.
pub fn describe(src: &str) -> Result<SchemaSummary> {
    Ok(scan(src))
}

fn scan(src: &str) -> SchemaSummary {
    let mut entities = Vec::new();
    let mut actions = Vec::new();
    let mut current_entity: Option<(String, Vec<AttrDef>)> = None;
    let mut in_entity = false;
    let mut in_action = false;
    let mut current_action: Option<(String, Option<String>)> = None;

    for raw in src.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if line.starts_with("entity ") {
            in_entity = true;
            in_action = false;
            if let Some((name, _)) = current_entity.take() {
                entities.push(EntityDef {
                    name,
                    kind: EntityKind::Entity,
                    attributes: vec![],
                });
            }
            let name = line
                .trim_start_matches("entity ")
                .trim_end_matches('{')
                .trim_end_matches(';')
                .trim()
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .unwrap_or("")
                .to_string();
            current_entity = Some((name, Vec::new()));
            if line.ends_with(';') || !line.contains('{') {
                if let Some((name, _)) = current_entity.take() {
                    entities.push(EntityDef {
                        name,
                        kind: EntityKind::Entity,
                        attributes: vec![],
                    });
                }
                in_entity = false;
            }
            continue;
        }
        if line.starts_with("action ") {
            in_action = true;
            in_entity = false;
            // Extract action id, possibly multiple per line.
            let rest = line.trim_start_matches("action ").trim_end_matches(';');
            // Take only the id token (e.g. "ToolCall::send_email").
            let id = rest
                .split(|c: char| !c.is_alphanumeric() && c != '_' && c != ':')
                .find(|s| !s.is_empty())
                .unwrap_or("")
                .to_string();
            current_action = Some((id, None));
            if !line.contains('{') || line.ends_with(';') {
                if let Some((id, _)) = current_action.take() {
                    actions.push(EntityDef {
                        name: id,
                        kind: EntityKind::Action,
                        attributes: vec![],
                    });
                }
                in_action = false;
            }
            continue;
        }
        if line == "}" || line == "};" {
            if in_entity {
                if let Some((name, _)) = current_entity.take() {
                    entities.push(EntityDef {
                        name,
                        kind: EntityKind::Entity,
                        attributes: vec![],
                    });
                }
                in_entity = false;
            } else if in_action {
                if let Some((id, _)) = current_action.take() {
                    actions.push(EntityDef {
                        name: id,
                        kind: EntityKind::Action,
                        attributes: vec![],
                    });
                }
                in_action = false;
            }
            continue;
        }
        // Attribute lines (very loose parser).
        if in_entity || in_action {
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim().trim_end_matches('?').to_string();
                let v = v
                    .trim()
                    .trim_end_matches(',')
                    .trim_end_matches(';')
                    .to_string();
                if !k.is_empty() {
                    let attr = AttrDef {
                        name: k,
                        ty: v,
                        required: !line.contains('?'),
                    };
                    if in_entity {
                        if let Some((_, ref mut attrs)) = current_entity {
                            attrs.push(attr);
                        }
                    } else if in_action {
                        // We don't add attributes to actions for now.
                    }
                }
            }
        }
    }

    SchemaSummary { entities, actions }
}

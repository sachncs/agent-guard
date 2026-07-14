//! Build `cedar_policy::Entities` from JSON values.

use crate::error::Result;
use cedar_policy::{Entities, Entity};

/// Build `Entities` from a list of entity JSON objects.
pub fn build_entities(items: Vec<serde_json::Value>) -> Result<Entities> {
    let mut ents: Vec<Entity> = Vec::with_capacity(items.len());
    for v in items {
        let s = serde_json::to_string(&v)?;
        let e = Entity::from_json_str(&s, None)
            .map_err(|e| crate::error::Error::Entities(e.to_string()))?;
        ents.push(e);
    }
    Entities::from_entities(ents, None).map_err(|e| crate::error::Error::Entities(e.to_string()))
}

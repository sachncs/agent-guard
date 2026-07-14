//! What-if simulator: evaluates a request and produces a detailed trace
//! including which policies fired, why, and what entity context was used.

use crate::authorize::{build_entities, Authorizer};
use crate::error::Result;
use crate::request::AgentRequest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub effect: String,
    pub policies: Vec<String>,
    pub reasons: Vec<String>,
    pub request: serde_json::Value,
    pub entity_count: usize,
}

pub struct Simulator {
    engine: Authorizer,
}

impl Simulator {
    pub fn new(engine: Authorizer) -> Self {
        Self { engine }
    }

    pub fn run(
        &self,
        req: &AgentRequest,
        entity_jsons: Vec<serde_json::Value>,
    ) -> Result<SimulationResult> {
        let entities = build_entities(entity_jsons)?;
        let decision = self.engine.authorize(req, &entities)?;
        Ok(SimulationResult {
            effect: format!("{:?}", decision.effect).to_lowercase(),
            policies: decision.policies,
            reasons: decision.reasons,
            request: serde_json::to_value(req)?,
            entity_count: entities.len(),
        })
    }
}

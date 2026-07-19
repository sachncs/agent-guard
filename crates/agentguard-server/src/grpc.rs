//! gRPC AccessEvaluation service.
//!
//! Mirrors the HTTP `/access/v1/evaluation` endpoint so a PEP can
//! pick its transport. Same Authorizer, same DecisionLog, same
//! auth_layer — the gRPC handler delegates to the shared
//! `evaluation_request_to_agent` helper to keep principal/action/
//! resource semantics identical across transports.

use crate::authzen::{build_request_entities, evaluation_request_to_agent, AppState};
use crate::proto::agentguard::v1::{
    access_evaluation_server::{AccessEvaluation, AccessEvaluationServer},
    EvaluationRequest as PbRequest, EvaluationResponse as PbResponse,
};
use agentguard_core::Effect;
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// The service implementation. Cheap to clone (internally Arc).
#[derive(Clone)]
pub struct AccessEvaluationService {
    state: Arc<AppState>,
}

impl AccessEvaluationService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl AccessEvaluation for AccessEvaluationService {
    async fn evaluation(
        &self,
        request: Request<PbRequest>,
    ) -> Result<Response<PbResponse>, Status> {
        let req = request.into_inner();
        let subject = req.subject.ok_or_else(|| Status::invalid_argument("missing subject"))?;
        let action = req.action.ok_or_else(|| Status::invalid_argument("missing action"))?;
        let resource = req
            .resource
            .ok_or_else(|| Status::invalid_argument("missing resource"))?;

        // Convert proto EntityRef -> AuthZEN JSON shape -> AgentRequest.
        let http_style = crate::authzen::EvaluationRequest {
            subject: crate::authzen::EntityRef {
                entity_type: subject.r#type,
                id: subject.id,
            },
            action: crate::authzen::EntityRef {
                entity_type: action.r#type,
                id: action.id,
            },
            resource: crate::authzen::EntityRef {
                entity_type: resource.r#type,
                id: resource.id,
            },
            context: if req.context_json.is_empty() {
                serde_json::json!({})
            } else {
                serde_json::from_str(&req.context_json)
                    .map_err(|e| Status::invalid_argument(format!("context_json: {e}")))?
            },
            entities: if req.entities_json.is_empty() {
                vec![]
            } else {
                serde_json::from_str(&req.entities_json)
                    .map_err(|e| Status::invalid_argument(format!("entities_json: {e}")))?
            },
        };

        let agent_req = evaluation_request_to_agent(http_style)
            .map_err(Status::invalid_argument)?;
        let per_request_entities: Vec<serde_json::Value> = if req.entities_json.is_empty() {
            vec![]
        } else {
            serde_json::from_str(&req.entities_json)
                .map_err(|e| Status::invalid_argument(format!("entities_json: {e}")))?
        };
        let entities = build_request_entities(&per_request_entities)
            .map_err(Status::internal)?;

        let started = std::time::Instant::now();
        let outcome = self.state.authorizer().authorize(&agent_req, &entities);
        let elapsed = started.elapsed();
        let decision = outcome.map_err(|e| {
            self.state.metrics().record_pdp_error("grpc_authorize");
            Status::internal(format!("authorize failed: {e}"))
        })?;

        let effect_label = match decision.effect {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
        };
        let action_label = format!("{}", agent_req.action);
        let policy_id = decision
            .policies
            .first()
            .cloned()
            .unwrap_or_else(|| "none".into());
        self.state.metrics().record_decision(
            effect_label,
            &policy_id,
            &action_label,
            "",
            elapsed,
        );
        if decision.from_cache {
            self.state.metrics().record_cache_hit();
        } else {
            self.state.metrics().record_cache_miss();
        }

        if let Some(audit) = self.state.audit() {
            if let Err(e) = audit.append_decision(&decision) {
                self.state.metrics().record_pdp_error("audit_append");
                return Err(Status::internal(format!("audit log unavailable: {e}")));
            }
        }

        Ok(Response::new(PbResponse {
            decision: matches!(decision.effect, Effect::Allow),
            reason: decision.reasons.first().cloned().unwrap_or_default(),
            context_json: String::new(),
        }))
    }
}

/// Return the tonic-wrapped service ready to mount on a `Server`.
pub fn service(state: Arc<AppState>) -> AccessEvaluationServer<AccessEvaluationService> {
    AccessEvaluationServer::new(AccessEvaluationService::new(state))
}

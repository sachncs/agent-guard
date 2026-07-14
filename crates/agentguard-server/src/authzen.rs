//! AuthZEN HTTP endpoint types and handlers.
//!
//! Reference: <https://openid.github.io/authzen/> (OpenID AuthZEN WG draft).

use agentguard_core::authorize::entities::build_entities;
use agentguard_core::observability::TraceContext;
use agentguard_core::{AgentRequest, Authorizer, Effect, PolicyStore};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use cedar_policy::Entities;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// OpenID AuthZEN EvaluationRequest (subject/action/resource/context).
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthZenEvaluationRequest {
    pub subject: AuthZenEntityRef,
    pub action: AuthZenEntityRef,
    pub resource: AuthZenEntityRef,
    #[serde(default)]
    pub context: serde_json::Value,
}

/// Subject/Action/Resource reference: a single entity.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthZenEntityRef {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub id: String,
}

/// AuthZEN EvaluationResponse.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthZenEvaluationResponse {
    /// `true` = allow, `false` = deny.
    pub decision: bool,
    /// Optional context to return to the PEP (e.g. acr_values for step-up).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
    /// Optional reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Batch evaluation semantics.
#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationSemantics {
    /// Run every evaluation regardless of decisions.
    #[default]
    ExecuteAll,
    /// Stop and deny on first deny.
    DenyOnFirstDeny,
    /// Stop and permit on first permit.
    PermitOnFirstPermit,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthZenEvaluationsRequest {
    pub evaluations: Vec<AuthZenEvaluationRequest>,
    #[serde(default)]
    pub evaluation_semantics: Option<EvaluationSemantics>,
    #[serde(default)]
    pub subject: Option<AuthZenEntityRef>,
    #[serde(default)]
    pub resource: Option<AuthZenEntityRef>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthZenEvaluationsResponse {
    pub evaluations: Vec<AuthZenEvaluationResponse>,
}

/// Shared state for HTTP handlers.
#[derive(Clone)]
pub struct AppState {
    pub authorizer: Arc<Authorizer>,
}

/// Build the AuthZEN HTTP router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/access/v1/evaluation", post(evaluation))
        .route("/access/v1/evaluations", post(evaluations))
        .route("/healthz", axum::routing::get(healthz))
        .route("/readyz", axum::routing::get(readyz))
        // Cap request bodies at 64 KB. AuthZEN requests are small JSON; anything
        // larger is either misconfigured or an attack.
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        // Inject/propagate W3C Trace Context for every request. If the
        // caller sent a `traceparent` header, we honor it; otherwise we
        // generate a fresh root span. The span id is added to every
        // response as the `x-agentguard-span-id` header so callers can
        // correlate logs and decisions.
        .layer(from_fn(trace_context_layer))
        .with_state(state)
}

/// W3C Trace Context middleware: read incoming `traceparent` or generate
/// a fresh trace, and echo the span id back to the caller.
async fn trace_context_layer(
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Response {
    let traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<TraceContext>().ok());
    let trace = traceparent.unwrap_or_else(TraceContext::fresh);
    // Generate a child span for this request handling hop.
    let child = trace.child();
    let span_id = child.span_id;

    // Stash the parsed trace in request extensions so handlers can use it
    // (e.g. to attach to a DecisionRecord).
    req.extensions_mut().insert(child);

    let mut response = next.run(req).await;
    if let Ok(v) = HeaderValue::from_str(&span_id.to_string()) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-agentguard-span-id"), v);
    }
    response
}

async fn healthz() -> &'static str {
    "ok\n"
}

async fn readyz(State(state): State<AppState>) -> &'static str {
    if state.authorizer.policies().policies().count() > 0 {
        "ok\n"
    } else {
        "loading\n"
    }
}

fn evaluation_request_to_agent(req: AuthZenEvaluationRequest) -> Result<AgentRequest, String> {
    let principal = agentguard_core::Principal::user(req.subject.id.clone());
    // AuthZEN action.id is the full action UID like "ToolCall::send_email".
    // Strip the leading "ToolCall::" to fit agentguard's AgentAction shape.
    let action_id = req
        .action
        .id
        .strip_prefix("ToolCall::")
        .unwrap_or(&req.action.id)
        .to_string();
    let action = if let Some((tool, op)) = action_id.split_once("::") {
        agentguard_core::AgentAction::tool_op(tool, op)
    } else {
        agentguard_core::AgentAction::tool(action_id)
    };
    let resource = agentguard_core::Resource::new(req.resource.entity_type, req.resource.id);
    let mut context = agentguard_core::AgentContext::new();
    if let serde_json::Value::Object(map) = &req.context {
        for (k, v) in map {
            if k == "session" {
                if let serde_json::Value::Object(session_map) = v {
                    for (sk, sv) in session_map {
                        context = context.with_session(sk, sv.clone());
                    }
                }
            } else if k == "trace" {
                // trace is parsed separately in Stage 8 — skip for now.
            } else {
                context = context.with_arg(k, v.clone());
            }
        }
    }
    Ok(AgentRequest::new(principal, action, resource, context))
}

async fn evaluation(
    State(state): State<AppState>,
    Json(req): Json<AuthZenEvaluationRequest>,
) -> Response {
    let agent_req = match evaluation_request_to_agent(req) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let entities = Entities::empty();
    match state.authorizer.authorize(&agent_req, &entities) {
        Ok(decision) => {
            let resp = AuthZenEvaluationResponse {
                decision: matches!(decision.effect, Effect::Allow),
                context: None,
                reason: decision.reasons.first().cloned(),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("authorize: {}", e),
        )
            .into_response(),
    }
}

async fn evaluations(
    State(state): State<AppState>,
    Json(req): Json<AuthZenEvaluationsRequest>,
) -> Response {
    let semantics = req.evaluation_semantics.unwrap_or_default();
    let entities = Entities::empty();
    let mut responses = Vec::with_capacity(req.evaluations.len());

    for er in req.evaluations {
        let agent_req = match evaluation_request_to_agent(er) {
            Ok(r) => r,
            Err(e) => {
                return (StatusCode::BAD_REQUEST, e).into_response();
            }
        };
        match state.authorizer.authorize(&agent_req, &entities) {
            Ok(decision) => {
                let allow = matches!(decision.effect, Effect::Allow);
                responses.push(AuthZenEvaluationResponse {
                    decision: allow,
                    context: None,
                    reason: decision.reasons.first().cloned(),
                });
                match semantics {
                    EvaluationSemantics::DenyOnFirstDeny if !allow => break,
                    EvaluationSemantics::PermitOnFirstPermit if allow => break,
                    _ => {}
                }
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("authorize: {}", e),
                )
                    .into_response();
            }
        }
    }

    (
        StatusCode::OK,
        Json(AuthZenEvaluationsResponse {
            evaluations: responses,
        }),
    )
        .into_response()
}

/// Build an [`AppState`] from a policy store on disk.
pub async fn build_state(store_root: std::path::PathBuf) -> Result<AppState, String> {
    let store = PolicyStore::open(&store_root).map_err(|e| format!("open store: {}", e))?;
    let authorizer = Arc::new(Authorizer::new(store).map_err(|e| format!("authorizer: {}", e))?);
    Ok(AppState { authorizer })
}

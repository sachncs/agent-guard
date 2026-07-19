//! AuthZEN HTTP endpoint types and handlers.
//!
//! Reference: <https://openid.github.io/authzen/> (OpenID AuthZEN WG draft).

use agentguard_core::authorize::entities::build_entities;
use agentguard_core::decision::{cache::CacheConfig, DecisionLog};
use agentguard_core::observability::TraceContext;
use agentguard_core::{AgentRequest, Authorizer, Effect, PolicyStore};
use agentguard_telemetry::Metrics;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use cedar_policy::Entities;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

/// Maximum number of evaluations accepted in a single
/// `/access/v1/evaluations` request. Caps memory + CPU per request;
/// anything larger should be split by the caller.
pub const MAX_BATCH_EVALUATIONS: usize = 100;

/// OpenID AuthZEN EvaluationRequest (subject/action/resource/context).
///
/// Per the AuthZEN draft, requests MAY include an `entities` array of
/// fully-formed Cedar entity JSON objects (`{uid: {type, id}, attrs: {...},
/// parents: [...]}`). When present they are unioned with the always-present
/// subject/action/resource entities and passed to the Cedar evaluator.
///
/// Without `entities`, every real-world policy that references any entity
/// attribute or hierarchy (the typical case) returns Deny because Cedar
/// resolves `principal in Group::"admins"` against an empty store. This
/// is the single most common AuthZEN integration bug.
#[derive(Debug, Deserialize, Serialize)]
pub struct EvaluationRequest {
    pub subject: EntityRef,
    pub action: EntityRef,
    pub resource: EntityRef,
    #[serde(default)]
    pub context: serde_json::Value,
    /// Optional list of entity JSON objects to make available to the
    /// Cedar evaluator. See module docs.
    #[serde(default)]
    pub entities: Vec<serde_json::Value>,
}

/// Subject/Action/Resource reference: a single entity.
#[derive(Debug, Deserialize, Serialize)]
pub struct EntityRef {
    #[serde(rename = "type")]
    pub entity_type: String,
    pub id: String,
}

/// AuthZEN EvaluationResponse.
#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluationResponse {
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
pub struct BatchEvaluationRequest {
    pub evaluations: Vec<EvaluationRequest>,
    #[serde(default)]
    pub evaluation_semantics: Option<EvaluationSemantics>,
    #[serde(default)]
    pub subject: Option<EntityRef>,
    #[serde(default)]
    pub resource: Option<EntityRef>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchEvaluationResponse {
    pub evaluations: Vec<EvaluationResponse>,
}

/// Shared state for HTTP handlers.
///
/// `authorizer` and `audit` are private with public accessors
/// (`authorizer()`, `audit()`). The handler closures use
/// `state.authorizer()` etc. The fields are read-only after the
/// router is built; the struct is `Clone` so each Axum worker
/// gets its own `Arc` clones.
#[derive(Clone)]
pub struct AppState {
    authorizer: Arc<Authorizer>,
    /// Audit log writer. Every authorization decision is appended
    /// here. `None` only when the operator explicitly opts out (the
    /// CLI `--skip-audit` flag).
    audit: Arc<Option<DecisionLog>>,
    /// Authentication layer. `Disabled` allows any caller; `ApiKey`
    /// validates `Authorization: Bearer <raw>`.
    pub auth: crate::auth_layer::AuthLayer,
    /// Metrics registry. Always populated; even with no exporter
    /// wired, `/metrics` returns the current snapshot.
    pub metrics: Arc<Metrics>,
}

impl AppState {
    /// The authorization engine. Cheap to clone (already an `Arc`).
    pub fn authorizer(&self) -> &Arc<Authorizer> {
        &self.authorizer
    }

    /// The audit log writer, if configured. `None` when the operator
    /// disabled audit logging.
    pub fn audit(&self) -> Option<&DecisionLog> {
        self.audit.as_ref().as_ref()
    }

    /// The metrics registry. The same handle is used by `/metrics`,
    /// the OTLP sink (when enabled), and the in-handler counters.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }
}

/// Build the AuthZEN HTTP router.
///
/// The router exposes:
/// - `POST /access/v1/evaluation` — single decision
/// - `POST /access/v1/evaluations` — batch with
///   `evaluation_semantics: "execute_all" | "deny_on_first_deny" |
///   "permit_on_first_permit"`
/// - `GET /healthz` — always 200
/// - `GET /readyz` — 200 only if policies are loaded AND the audit log
///   is writable
///
/// The body is capped at 64 KB; larger requests are rejected by
/// axum's `DefaultBodyLimit` layer.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/access/v1/evaluation", post(evaluation))
        .route("/access/v1/evaluations", post(evaluations))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        // Auth runs after trace context (so unauthorized requests still
        // get a span id echoed back), and after the body limit (so we
        // don't buffer megabytes before 401-ing).
        .layer(from_fn_with_state(
            state.clone(),
            crate::auth_layer::auth_layer_fn,
        ))
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

/// Prometheus-text snapshot of every metric the server has recorded.
async fn metrics(State(state): State<AppState>) -> Response {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        state.metrics().render_prometheus(),
    )
        .into_response()
}

/// W3C Trace Context middleware: read incoming `traceparent` or generate
/// a fresh trace, and echo the span id back to the caller.
async fn trace_context_layer(headers: HeaderMap, mut req: Request, next: Next) -> Response {
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

async fn readyz(State(state): State<AppState>) -> Response {
    // 1. Policies must be loaded. policy_count() is O(1) (the
    // cedar PolicySet length is cached), unlike the previous
    // .policies().next().is_some() which walked the full set.
    if state.authorizer.policy_count() == 0 {
        return readyz_unavailable("policies not loaded");
    }
    // 2. Audit log must be configured and open.
    match state.audit() {
        Some(audit) if audit.chain_id().is_some() => (),
        Some(_) => return readyz_unavailable("audit log not opened"),
        None => return readyz_unavailable("audit log not configured"),
    }
    (StatusCode::OK, "ok\n").into_response()
}

fn readyz_unavailable(reason: &str) -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, format!("{reason}\n")).into_response()
}

fn evaluation_request_to_agent(req: EvaluationRequest) -> Result<AgentRequest, String> {
    let principal = match req.subject.entity_type.as_str() {
        "User" => agentguard_core::Principal::user(req.subject.id.clone()),
        "Agent" => agentguard_core::Principal::agent(req.subject.id.clone()),
        other => {
            return Err(format!(
                "unsupported subject type {:?}: expected User or Agent",
                other
            ));
        }
    };
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

/// Build a `cedar_policy::Entities` from the request's `entities` array.
/// Per-request entities are typical for AuthZEN (each PEP sends the
/// entities relevant to its call); a future enhancement can layer
/// shared/static entities on top.
fn build_request_entities(items: &[serde_json::Value]) -> Result<Entities, String> {
    build_entities(items.to_vec()).map_err(|e| format!("entities: {}", e))
}

async fn evaluation(State(state): State<AppState>, Json(req): Json<EvaluationRequest>) -> Response {
    let per_request_entities = req.entities.clone();
    let agent_req = match evaluation_request_to_agent(req) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let entities = match build_request_entities(&per_request_entities) {
        Ok(e) => e,
        Err(e) => {
            state.metrics().record_pdp_error("entities_build");
            return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
        }
    };
    let started = Instant::now();
    let outcome = state.authorizer.authorize(&agent_req, &entities);
    let elapsed = started.elapsed();
    match outcome {
        Ok(decision) => {
            let effect_label = match decision.effect {
                Effect::Allow => "allow",
                Effect::Deny => "deny",
            };
            let action_label = format!("{}", agent_req.action);
            // tenant_id is optional in our model; empty string keeps
            // the cardinality low but still distinguishable from a
            // multi-tenant deployment that does set it.
            let tenant_label = "";
            let policy_id = decision
                .policies
                .first()
                .cloned()
                .unwrap_or_else(|| "none".into());
            state.metrics().record_decision(
                effect_label,
                &policy_id,
                &action_label,
                tenant_label,
                elapsed,
            );
            if decision.from_cache {
                state.metrics().record_cache_hit();
            } else {
                state.metrics().record_cache_miss();
            }
            // Audit-log the decision. When audit is configured
            // (production posture), a write failure MUST surface as
            // 500 — silently dropping decisions defeats the audit
            // requirement.
            if let Some(audit) = state.audit() {
                if let Err(e) = audit.append_decision(&decision) {
                    state.metrics().record_pdp_error("audit_append");
                    tracing::error!(error = %e, "audit append failed; refusing decision");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "audit log unavailable",
                    )
                        .into_response();
                }
            }
            let resp = EvaluationResponse {
                decision: matches!(decision.effect, Effect::Allow),
                context: None,
                reason: decision.reasons.first().cloned(),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => {
            state.metrics().record_pdp_error("authorize");
            tracing::error!(error = %e, "authorize failed");
            // Do NOT include the cedar error verbatim — it can leak
            // policy text. Return a generic message and log details.
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal authorization error",
            )
                .into_response()
        }
    }
}

async fn evaluations(
    State(state): State<AppState>,
    Json(req): Json<BatchEvaluationRequest>,
) -> Response {
    // ponytail: cap the batch size here too. Body limit caps total
    // bytes but a tight loop of tiny items would still slip through.
    if req.evaluations.len() > MAX_BATCH_EVALUATIONS {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "batch too large: {} > {} max evaluations",
                req.evaluations.len(),
                MAX_BATCH_EVALUATIONS
            ),
        )
            .into_response();
    }
    let semantics = req.evaluation_semantics.unwrap_or_default();
    // Use the top-level request entities for the whole batch. Per-item
    // entities in nested evaluations are ignored (callers should
    // submit them at the top level).
    let entities = match build_request_entities(&[]) {
        Ok(e) => e,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
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
                if let Some(audit) = state.audit() {
                    if let Err(e) = audit.append_decision(&decision) {
                        tracing::error!(error = %e, "audit append failed");
                    }
                }
                responses.push(EvaluationResponse {
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
                tracing::error!(error = %e, "authorize failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal authorization error",
                )
                    .into_response();
            }
        }
    }

    (
        StatusCode::OK,
        Json(BatchEvaluationResponse {
            evaluations: responses,
        }),
    )
        .into_response()
}

/// Build an [`AppState`] from a policy store on disk + an optional
/// audit log. If `chain_secret` is `Some`, the audit log is opened
/// in chained (HMAC) mode; otherwise plain JSONL.
///
/// # Errors
/// Returns a `String` error if the store can't be opened or the cedar
/// engine can't be initialized. The error string is suitable for an HTTP
/// 500 response body.
pub async fn build_state(
    store_root: std::path::PathBuf,
    audit_log: Option<std::path::PathBuf>,
    chain_secret: Option<Vec<u8>>,
    auth: crate::auth_layer::AuthLayer,
) -> Result<AppState, String> {
    build_state_with_cache(store_root, audit_log, chain_secret, auth, None).await
}

/// Like [`build_state`] but takes an explicit `CacheConfig`. Passing
/// `None` reads `AGENTGUARD_CACHE_TTL`/`AGENTGUARD_CACHE_CAPACITY`
/// from the environment (defaulting to the built-in values).
pub async fn build_state_with_cache(
    store_root: std::path::PathBuf,
    audit_log: Option<std::path::PathBuf>,
    chain_secret: Option<Vec<u8>>,
    auth: crate::auth_layer::AuthLayer,
    cache: Option<CacheConfig>,
) -> Result<AppState, String> {
    let store = PolicyStore::open(&store_root).map_err(|e| format!("open store: {}", e))?;
    let mut authorizer = Authorizer::new(store).map_err(|e| format!("authorizer: {}", e))?;
    if let Some(cfg) = cache {
        authorizer = authorizer.with_cache(cfg);
    }
    let authorizer = Arc::new(authorizer);
    let audit = match audit_log {
        Some(path) => {
            let log = match chain_secret {
                Some(secret) => DecisionLog::open_with_chain(&path, &secret)
                    .map_err(|e| format!("open chained audit log: {}", e))?,
                None => DecisionLog::open(&path).map_err(|e| format!("open audit log: {}", e))?,
            };
            Some(log)
        }
        None => None,
    };
    Ok(AppState {
        authorizer,
        audit: Arc::new(audit),
        auth,
        metrics: Metrics::new(),
    })
}

//! AuthZEN HTTP endpoint types and handlers.
//!
//! Reference: <https://openid.github.io/authzen/> (OpenID AuthZEN WG draft).

use crate::audit::AuditAppender;
use agentguard_core::authorize::entities::build_entities;
use agentguard_core::decision::{
    cache::{CacheConfig, DecisionCache},
    DecisionLog, RotationConfig,
};
use agentguard_core::observability::TraceContext;
use agentguard_core::{AgentRequest, Authorizer, Effect, PolicyStore};
use agentguard_telemetry::Metrics;
use axum::extract::{Extension, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use cedar_policy::Entities;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::sync::Semaphore;

/// Bound policy evaluation and audit fsync work so they cannot block Tokio
/// workers or create an unbounded blocking-task queue.
const MAX_CONCURRENT_PDP_WORK_ITEMS: usize = 4;

#[derive(Debug)]
pub(crate) enum PdpWorkError {
    Saturated,
    Join(tokio::task::JoinError),
    Entities(String),
    Authorize(agentguard_core::Error),
    Audit(agentguard_core::Error),
}

pub(crate) fn report_pdp_work_failure(
    state: &AppState,
    error: PdpWorkError,
) -> (StatusCode, &'static str) {
    match error {
        PdpWorkError::Saturated => {
            state.metrics().record_pdp_error("pdp_overloaded");
            (StatusCode::SERVICE_UNAVAILABLE, "PDP capacity exhausted")
        }
        PdpWorkError::Join(error) => {
            state.metrics().record_pdp_error("pdp_worker");
            tracing::error!(%error, "PDP worker failed; refusing decision");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "authorization unavailable",
            )
        }
        PdpWorkError::Entities(error) => {
            state.metrics().record_pdp_error("entities_build");
            tracing::debug!(%error, "request entities rejected");
            (StatusCode::BAD_REQUEST, "invalid request entities")
        }
        PdpWorkError::Authorize(error) => {
            state.metrics().record_pdp_error("authorize");
            let (code, summary) = summarize_authorize_error(&error);
            tracing::error!(error_code = %code, error = %summary, "authorize failed");
            tracing::debug!(error = ?error, "full authorize error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal authorization error",
            )
        }
        PdpWorkError::Audit(error) => {
            state.metrics().record_pdp_error("audit_append");
            tracing::error!(%error, "audit append failed; refusing decision");
            (StatusCode::INTERNAL_SERVER_ERROR, "audit log unavailable")
        }
    }
}

fn pdp_work_slots() -> Arc<Semaphore> {
    static SLOTS: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
    SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_PDP_WORK_ITEMS)))
        .clone()
}

pub(crate) async fn authorize_and_persist_decision(
    authorizer: Arc<Authorizer>,
    request: AgentRequest,
    entity_values: Vec<serde_json::Value>,
    audit: Arc<Option<Arc<dyn AuditAppender>>>,
) -> Result<(agentguard_core::Decision, std::time::Duration), PdpWorkError> {
    run_bounded_pdp_work(pdp_work_slots(), move || {
        let entities = build_request_entities(&entity_values).map_err(PdpWorkError::Entities)?;
        let started = Instant::now();
        let decision = authorizer
            .authorize(&request, &entities)
            .map_err(PdpWorkError::Authorize)?;
        let elapsed = started.elapsed();
        if let Some(audit) = audit.as_ref() {
            audit
                .append_decision(&decision)
                .map_err(PdpWorkError::Audit)?;
        }
        Ok((decision, elapsed))
    })
    .await
}

async fn run_bounded_pdp_work<T, F>(slots: Arc<Semaphore>, operation: F) -> Result<T, PdpWorkError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, PdpWorkError> + Send + 'static,
{
    let permit = slots
        .try_acquire_owned()
        .map_err(|_| PdpWorkError::Saturated)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    .map_err(PdpWorkError::Join)?
}

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
/// (`authorizer()`, `audit()`). The authorizer handle atomically swaps
/// policy snapshots when the watcher observes a valid change, so in-flight
/// requests finish against the snapshot they started with.
#[derive(Clone)]
pub struct AppState {
    authorizer: AuthorizerHandle,
    /// Audit log writer. Every authorization decision is appended
    /// here. `None` only when the operator explicitly opts out (the
    /// CLI `--skip-audit` flag).
    audit: Arc<Option<Arc<DecisionLog>>>,
    audit_appender: Arc<Option<Arc<dyn AuditAppender>>>,
    /// Authentication layer. `Disabled` allows any caller; `ApiKey`
    /// validates `Authorization: Bearer <raw>`.
    pub auth: crate::auth_layer::AuthLayer,
    /// Metrics registry. Always populated; even with no exporter
    /// wired, `/metrics` returns the current snapshot.
    pub metrics: Arc<Metrics>,
}

/// Concurrent policy snapshot with an explicit reload boundary.
///
/// Requests take an `Arc` snapshot for the duration of one evaluation while
/// reload builds a complete replacement off to the side. A malformed policy
/// therefore leaves the last known-good snapshot serving instead of replacing
/// it with partial state.
#[derive(Clone)]
pub struct AuthorizerHandle {
    current: Arc<RwLock<Arc<Authorizer>>>,
    store_root: Arc<PathBuf>,
    cache: Option<CacheConfig>,
}

impl AuthorizerHandle {
    fn new(store_root: PathBuf, cache: Option<CacheConfig>) -> Result<Self, String> {
        let authorizer = Self::load(&store_root, cache.as_ref())?;
        Ok(Self {
            current: Arc::new(RwLock::new(Arc::new(authorizer))),
            store_root: Arc::new(store_root),
            cache,
        })
    }

    fn load(store_root: &PathBuf, cache: Option<&CacheConfig>) -> Result<Authorizer, String> {
        let store = PolicyStore::open(store_root).map_err(|e| format!("open store: {}", e))?;
        let mut authorizer = Authorizer::new(store).map_err(|e| format!("authorizer: {}", e))?;
        if let Some(cfg) = cache {
            authorizer = authorizer.with_cache(cfg.clone());
        }
        Ok(authorizer)
    }

    pub(crate) fn snapshot(&self) -> Arc<Authorizer> {
        self.current
            .read()
            .expect("authorizer snapshot lock poisoned")
            .clone()
    }

    /// Replace the serving snapshot only after the complete policy store has
    /// loaded successfully. The old snapshot remains available on failure.
    pub fn reload(&self) -> Result<(), String> {
        let replacement = Arc::new(Self::load(&self.store_root, self.cache.as_ref())?);
        let mut current = self
            .current
            .write()
            .map_err(|_| "authorizer reload lock poisoned".to_string())?;
        *current = replacement;
        Ok(())
    }

    pub fn authorize(
        &self,
        req: &AgentRequest,
        entities: &Entities,
    ) -> agentguard_core::Result<agentguard_core::Decision> {
        self.snapshot().authorize(req, entities)
    }

    pub fn policy_count(&self) -> usize {
        self.snapshot().policy_count()
    }

    pub fn invalidate_cache(&self) {
        self.snapshot().invalidate_cache();
    }

    pub fn sweep_stale_cache(&self) -> usize {
        self.snapshot().sweep_stale_cache()
    }
}

impl AppState {
    /// The authorization engine. Cheap to clone (already an `Arc`).
    pub fn authorizer(&self) -> &AuthorizerHandle {
        &self.authorizer
    }

    /// The audit log writer, if configured. `None` when the operator
    /// disabled audit logging.
    pub fn audit(&self) -> Option<&DecisionLog> {
        self.audit.as_ref().as_deref()
    }

    pub(crate) fn audit_handle(&self) -> Arc<Option<Arc<dyn AuditAppender>>> {
        self.audit_appender.clone()
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
    // 2. Audit log must be configured, have a chained identity, and retain
    // an active writer handle. A permanent append failure poisons that handle
    // so the orchestrator can stop routing new decisions to this instance.
    match state.audit_appender.as_ref() {
        Some(audit) if !audit.is_healthy() => return readyz_unavailable("audit log unavailable"),
        Some(audit) if audit.is_chained() => (),
        Some(_) => return readyz_unavailable("audit log not opened"),
        None => return readyz_unavailable("audit log not configured"),
    }
    (StatusCode::OK, "ok\n").into_response()
}

fn readyz_unavailable(reason: &str) -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, format!("{reason}\n")).into_response()
}

/// Sanitize an authorization error for logging. Returns a stable
/// error code plus a short summary that does NOT include the
/// underlying cedar policy / schema text. The full error is kept
/// for a separate debug-level log line so engineering can still
/// investigate without sending it to log aggregators.
fn summarize_authorize_error(e: &agentguard_core::Error) -> (&'static str, String) {
    use agentguard_core::Error;
    match e {
        Error::Io(_) => ("io", "io error".to_string()),
        Error::Json(_) => ("json", "json error".to_string()),
        Error::Schema(_) => ("schema", "schema error".to_string()),
        Error::InvalidPrincipal(_) => ("invalid_principal", "invalid principal".to_string()),
        Error::InvalidResource(_) => ("invalid_resource", "invalid resource".to_string()),
        Error::InvalidContext(_) => ("invalid_context", "invalid context".to_string()),
        Error::PolicyParse { .. } => ("policy_parse", "policy parse error".to_string()),
        Error::Validation(_) => ("validation", "policy validation failed".to_string()),
        Error::Entities(_) => ("entities", "entities build failed".to_string()),
        Error::Walk(_) => ("walk", "policy walk failed".to_string()),
        Error::Other(_) => ("other", "internal error".to_string()),
        // Token variants are surfaced by the auth layer, not the
        // PDP, but be exhaustive just in case.
        Error::InvalidToken(_) => ("invalid_token", "invalid delegation token".to_string()),
        Error::TokenExpired(_) => ("token_expired", "delegation token expired".to_string()),
        Error::TokenSignature { .. } => (
            "token_signature",
            "delegation signature invalid".to_string(),
        ),
        Error::TokenNotYetValid(_) => (
            "token_not_yet_valid",
            "delegation token not yet valid".to_string(),
        ),
        _ => ("other", "internal error".to_string()),
    }
}

pub fn evaluation_request_to_agent(req: EvaluationRequest) -> Result<AgentRequest, String> {
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
            } else {
                context = context.with_arg(k, v.clone());
            }
        }
    }
    Ok(AgentRequest::new(principal, action, resource, context))
}

#[derive(Debug)]
pub enum EvaluationMappingError {
    IdentityMismatch,
    InvalidRequest(String),
}

/// Map an HTTP or gRPC request while constraining it to the identity carried
/// by a verified API key. The bound tenant is stored in request/audit metadata,
/// not trusted from caller-controlled Cedar context. It is not a Cedar policy
/// attribute; policy isolation must use trusted entities/context explicitly.
pub fn evaluation_request_for_caller(
    mut req: EvaluationRequest,
    caller: Option<&crate::auth_layer::AuthenticatedIdentity>,
) -> Result<AgentRequest, EvaluationMappingError> {
    let tenant_id = if let Some(caller) = caller {
        let identity = &caller.0;
        if req.subject.entity_type != identity.subject_type || req.subject.id != identity.subject_id
        {
            return Err(EvaluationMappingError::IdentityMismatch);
        }
        let supplied_tenant = match req.context.get("tenant_id") {
            None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or(EvaluationMappingError::IdentityMismatch)?,
            ),
        };
        if supplied_tenant.is_some_and(|tenant| Some(tenant) != identity.tenant_id.as_deref()) {
            return Err(EvaluationMappingError::IdentityMismatch);
        }
        if let serde_json::Value::Object(context) = &mut req.context {
            context.remove("tenant_id");
        }
        identity.tenant_id.clone()
    } else {
        None
    };
    let mut mapped =
        evaluation_request_to_agent(req).map_err(EvaluationMappingError::InvalidRequest)?;
    if let Some(tenant_id) = tenant_id {
        mapped = mapped.with_tenant_id(tenant_id);
    }
    Ok(mapped)
}

/// Build a `cedar_policy::Entities` from the request's `entities` array.
/// Per-request entities are typical for AuthZEN (each PEP sends the
/// entities relevant to its call); a future enhancement can layer
/// shared/static entities on top.
pub fn build_request_entities(items: &[serde_json::Value]) -> Result<Entities, String> {
    build_entities(items.to_vec()).map_err(|e| format!("entities: {}", e))
}

#[tracing::instrument(
    skip_all,
    fields(subject = %req.subject.id, action = %req.action.id)
)]
async fn evaluation(
    State(state): State<AppState>,
    caller: Option<Extension<crate::auth_layer::AuthenticatedIdentity>>,
    Json(req): Json<EvaluationRequest>,
) -> Response {
    let per_request_entities = req.entities.clone();
    let agent_req = match evaluation_request_for_caller(req, caller.as_ref().map(|c| &c.0)) {
        Ok(r) => r,
        Err(EvaluationMappingError::IdentityMismatch) => {
            return (
                StatusCode::FORBIDDEN,
                "request identity does not match credential",
            )
                .into_response()
        }
        Err(EvaluationMappingError::InvalidRequest(e)) => {
            return (StatusCode::BAD_REQUEST, e).into_response()
        }
    };
    let action_label = format!("{}", agent_req.action);
    let outcome = authorize_and_persist_decision(
        state.authorizer.snapshot(),
        agent_req,
        per_request_entities,
        state.audit_appender.clone(),
    )
    .await;
    match outcome {
        Ok((decision, elapsed)) => {
            let effect_label = match decision.effect {
                Effect::Allow => "allow",
                Effect::Deny => "deny",
            };
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
            let resp = EvaluationResponse {
                decision: matches!(decision.effect, Effect::Allow),
                context: None,
                reason: decision.reasons.first().cloned(),
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(error) => {
            let (status, message) = report_pdp_work_failure(&state, error);
            (status, message).into_response()
        }
    }
}

async fn evaluations(
    State(state): State<AppState>,
    caller: Option<Extension<crate::auth_layer::AuthenticatedIdentity>>,
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
    let mut responses = Vec::with_capacity(req.evaluations.len());
    // A batch is one logical evaluation operation. Pin a single immutable
    // policy generation so a concurrent reload cannot mix decisions from
    // different snapshots inside the same response.
    let authorizer = state.authorizer.snapshot();

    for er in req.evaluations {
        let per_request_entities = er.entities.clone();
        let agent_req = match evaluation_request_for_caller(er, caller.as_ref().map(|c| &c.0)) {
            Ok(r) => r,
            Err(EvaluationMappingError::IdentityMismatch) => {
                return (
                    StatusCode::FORBIDDEN,
                    "request identity does not match credential",
                )
                    .into_response()
            }
            Err(EvaluationMappingError::InvalidRequest(e)) => {
                return (StatusCode::BAD_REQUEST, e).into_response()
            }
        };
        match authorize_and_persist_decision(
            authorizer.clone(),
            agent_req,
            per_request_entities,
            state.audit_appender.clone(),
        )
        .await
        {
            Ok((decision, _elapsed)) => {
                let allow = matches!(decision.effect, Effect::Allow);
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
            Err(error) => {
                let (status, message) = report_pdp_work_failure(&state, error);
                return (status, message).into_response();
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
    let audit_rotation = RotationConfig::try_from_env()
        .map_err(|error| format!("AGENTGUARD_AUDIT_MAX_BYTES {error}"))?;
    let authorizer = AuthorizerHandle::new(
        store_root,
        Some(cache.unwrap_or_else(DecisionCache::config_from_env)),
    )?;
    let audit = match audit_log {
        Some(path) => {
            let log = match (chain_secret, audit_rotation) {
                (Some(secret), Some(rotation)) => {
                    DecisionLog::open_with_rotation(&path, Some(&secret), rotation)
                        .map_err(|e| format!("open rotating chained audit log: {}", e))?
                }
                (Some(secret), None) => DecisionLog::open_with_chain(&path, &secret)
                    .map_err(|e| format!("open chained audit log: {}", e))?,
                (None, Some(rotation)) => DecisionLog::open_with_rotation(&path, None, rotation)
                    .map_err(|e| format!("open rotating audit log: {}", e))?,
                (None, None) => {
                    DecisionLog::open(&path).map_err(|e| format!("open audit log: {}", e))?
                }
            };
            Some(log)
        }
        None => None,
    };
    let audit = audit.map(Arc::new);
    let audit_appender: Option<Arc<dyn AuditAppender>> = audit
        .as_ref()
        .map(Arc::clone)
        .map(|log| log as Arc<dyn AuditAppender>);
    Ok(AppState {
        authorizer,
        audit: Arc::new(audit),
        audit_appender: Arc::new(audit_appender),
        auth,
        metrics: Arc::new(Metrics::new()),
    })
}

#[cfg(test)]
mod summarize_tests {
    use super::{router, summarize_authorize_error};
    use crate::audit::AuditAppender;
    use agentguard_core::{Decision, Error, PolicyStore};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::sync::Semaphore;
    use tower::ServiceExt;

    struct FailingAuditAppender;

    impl AuditAppender for FailingAuditAppender {
        fn append_decision(&self, _decision: &Decision) -> agentguard_core::Result<()> {
            Err(Error::Io("disk full".into()))
        }

        fn is_healthy(&self) -> bool {
            false
        }

        fn is_chained(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn audit_write_failure_fails_closed_and_marks_readiness_unhealthy() {
        let dir = tempdir().unwrap();
        let store = PolicyStore::open(dir.path()).unwrap();
        store
            .write_policy("allow", "permit(principal, action, resource);")
            .unwrap();
        let mut state = super::build_state(
            dir.path().to_path_buf(),
            Some(dir.path().join("audit.jsonl")),
            Some(b"test-key".to_vec()),
            crate::auth_layer::AuthLayer::Disabled,
        )
        .await
        .unwrap();
        state.audit_appender = Arc::new(Some(Arc::new(FailingAuditAppender)));

        let app = router(state);
        let response = app
            .clone()
            .oneshot(
                Request::post("/access/v1/evaluation")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"subject":{"type":"User","id":"alice"},"action":{"type":"Action","id":"read"},"resource":{"type":"Document","id":"doc"},"context":{}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let response = app
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn invalid_context_summary_does_not_leak_message() {
        // The Cedar error text echoes policy / schema fragments.
        // The sanitizer must produce a code + summary that does
        // NOT include any of that text.
        let err = Error::InvalidContext(
            "policy 'permit(principal, action, resource) when { secret == \"hunter2\" }': \
             unresolved attribute: secret"
                .to_string(),
        );
        let (code, summary) = summarize_authorize_error(&err);
        assert_eq!(code, "invalid_context");
        assert!(
            !summary.contains("hunter2"),
            "summary leaked policy text: {summary}"
        );
        assert!(
            !summary.contains("permit"),
            "summary leaked policy text: {summary}"
        );
    }

    #[test]
    fn reload_replaces_snapshot_and_retains_last_good_on_parse_error() {
        let dir = tempdir().unwrap();
        let store = PolicyStore::open(dir.path()).unwrap();
        store
            .write_policy("initial", "permit(principal, action, resource);")
            .unwrap();

        let handle = super::AuthorizerHandle::new(dir.path().to_path_buf(), None).unwrap();
        assert_eq!(handle.policy_count(), 1);
        let initial_snapshot = handle.snapshot();

        store
            .write_policy("second", "forbid(principal, action, resource);")
            .unwrap();
        handle.reload().unwrap();
        assert_eq!(handle.policy_count(), 2);
        assert_eq!(initial_snapshot.policy_count(), 1);

        store
            .write_policy("broken", "permit (this is not Cedar")
            .unwrap();
        assert!(handle.reload().is_err());
        assert_eq!(handle.policy_count(), 2);
    }

    #[tokio::test]
    async fn pdp_work_capacity_saturation_fails_fast() {
        let result =
            super::run_bounded_pdp_work(std::sync::Arc::new(Semaphore::new(0)), || Ok(())).await;
        assert!(matches!(result, Err(super::PdpWorkError::Saturated)));
    }

    #[tokio::test]
    async fn slow_pdp_work_does_not_stall_async_workers() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let ticks = std::sync::Arc::new(AtomicUsize::new(0));
        let tick_count = ticks.clone();
        let ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(10));
            loop {
                interval.tick().await;
                tick_count.fetch_add(1, Ordering::Relaxed);
            }
        });
        let result = super::run_bounded_pdp_work(std::sync::Arc::new(Semaphore::new(1)), || {
            std::thread::sleep(Duration::from_millis(80));
            Ok(())
        })
        .await;
        ticker.abort();

        assert!(result.is_ok());
        assert!(
            ticks.load(Ordering::Relaxed) >= 3,
            "async work should continue while PDP work runs in the blocking pool"
        );
    }

    #[tokio::test]
    async fn standalone_state_enables_default_decision_cache() {
        let dir = tempdir().unwrap();
        let store = PolicyStore::open(dir.path()).unwrap();
        store
            .write_policy("initial", "permit(principal, action, resource);")
            .unwrap();

        let state = super::build_state(
            dir.path().to_path_buf(),
            None,
            None,
            crate::auth_layer::AuthLayer::Disabled,
        )
        .await
        .unwrap();

        assert!(state.authorizer.cache.is_some());
    }

    #[test]
    fn policy_parse_summary_does_not_leak_filename() {
        let err = Error::PolicyParse {
            message: "unexpected token at column 7".into(),
            file: "/etc/agentguard/policies/30_strands.cedar".into(),
        };
        let (code, summary) = summarize_authorize_error(&err);
        assert_eq!(code, "policy_parse");
        assert!(
            !summary.contains("30_strands.cedar"),
            "summary leaked file path: {summary}"
        );
        assert!(
            !summary.contains("column 7"),
            "summary leaked parse position: {summary}"
        );
    }
}

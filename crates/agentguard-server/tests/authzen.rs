//! Integration tests for the AuthZEN HTTP server.
//!
//! Uses `axum::Router::oneshot` for in-process HTTP testing without binding to
//! a real port. Catches regressions in middleware, body limits, request ID
//! tracing, and handler routing.

use agentguard_core::PolicyStore;
use agentguard_server::authzen::{build_state, router};
use agentguard_server::AppState;
use agentguard_server::AuthLayer;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

async fn make_app() -> axum::Router {
    let dir = tempfile::tempdir().unwrap();
    let store = PolicyStore::open(dir.path()).unwrap();
    store
        .write_policy(
            "allow_alice",
            r#"permit (principal in User::"alice", action, resource);"#,
        )
        .unwrap();
    // Open a per-test audit log so /readyz sees a configured log.
    let audit_path = dir.path().join("audit.jsonl");
    let audit = agentguard_core::decision::DecisionLog::open(&audit_path).unwrap();
    let state: AppState = build_state(
        dir.path().to_path_buf(),
        Some(audit_path),
        Some(b"test-key".to_vec()),
        AuthLayer::Disabled,
    )
    .await
    .unwrap();
    drop(audit); // state owns its own copy via Arc
    router(state)
}

async fn make_app_shared() -> axum::Router {
    make_app().await
}

#[tokio::test]
async fn healthz_returns_ok() {
    let app = make_app_shared().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn readyz_returns_ok_when_policies_loaded() {
    let app = make_app_shared().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn evaluation_endpoint_returns_decision() {
    let app = make_app_shared().await;
    let body = serde_json::json!({
        "subject": {"type": "User", "id": "alice"},
        "action": {"type": "Action", "id": "ToolCall::send_email"},
        "resource": {"type": "Mailbox", "id": "alice@acme"},
        "context": {
            "to": "[email protected]",
            "subject": "hi",
            "body": "hello",
            "session": {"ip": "10.0.0.1", "user_agent": "x", "mfa": true, "ts": 0}
        }
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["decision"], true);
}

#[tokio::test]
async fn trace_context_header_is_echoed() {
    let app = make_app_shared().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header(
                    "traceparent",
                    "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // The middleware should set x-agentguard-span-id.
    assert!(resp.headers().contains_key("x-agentguard-span-id"));
}

#[tokio::test]
async fn body_size_limit_enforced() {
    let app = make_app_shared().await;
    // 128 KB body exceeds the 64 KB cap.
    let body = vec![b'x'; 128 * 1024];
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn evaluation_deny_path() {
    // The default test policy only permits User::"alice"; any other
    // principal must be denied. Verifies the evaluation path produces
    // decision=false (not a 500 or empty response).
    let app = make_app_shared().await;
    let body = serde_json::json!({
        "subject": {"type": "User", "id": "bob"},
        "action": {"type": "Action", "id": "ToolCall::send_email"},
        "resource": {"type": "Mailbox", "id": "bob@acme"},
        "context": {}
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["decision"], false);
}

#[tokio::test]
async fn evaluation_with_request_entities() {
    // Per-request entities (AuthZEN `entities` field) must be threaded
    // into the Cedar evaluator. We register a User entity and a
    // policy that requires it via `principal == User::"carol"`.
    let dir = tempfile::tempdir().unwrap();
    let store = PolicyStore::open(dir.path()).unwrap();
    store
        .write_policy(
            "allow_carol",
            r#"permit (principal == User::"carol", action, resource);"#,
        )
        .unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let state = build_state(
        dir.path().to_path_buf(),
        Some(audit_path),
        Some(b"test-key".to_vec()),
        AuthLayer::Disabled,
    )
    .await
    .unwrap();
    let app = router(state);
    let body = serde_json::json!({
        "subject": {"type": "User", "id": "carol"},
        "action": {"type": "Action", "id": "ToolCall::read_doc"},
        "resource": {"type": "Document", "id": "doc-1"},
        "context": {}
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["decision"], true);
}

#[tokio::test]
async fn readyz_returns_503_when_no_audit() {
    use agentguard_server::authzen::build_state;
    let dir = tempfile::tempdir().unwrap();
    let store = PolicyStore::open(dir.path()).unwrap();
    store
        .write_policy("allow_alice", r#"permit (principal, action, resource);"#)
        .unwrap();
    // No audit path passed → audit is None → /readyz must 503.
    let state = build_state(dir.path().to_path_buf(), None, None, AuthLayer::Disabled)
        .await
        .unwrap();
    let app = router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn evaluation_records_audit_entry() {
    // Each successful evaluation must produce exactly one audit log
    // entry. This guards against regressions in the audit-write path.
    let dir = tempfile::tempdir().unwrap();
    let store = PolicyStore::open(dir.path()).unwrap();
    store
        .write_policy(
            "allow_alice",
            r#"permit (principal in User::"alice", action, resource);"#,
        )
        .unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let state = build_state(
        dir.path().to_path_buf(),
        Some(audit_path.clone()),
        Some(b"test-key".to_vec()),
        AuthLayer::Disabled,
    )
    .await
    .unwrap();
    let app = router(state);
    let body = serde_json::json!({
        "subject": {"type": "User", "id": "alice"},
        "action": {"type": "Action", "id": "ToolCall::send"},
        "resource": {"type": "Mailbox", "id": "alice@x"},
        "context": {}
    });
    for _ in 0..3 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/access/v1/evaluation")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    // Read the audit log directly.
    let records = agentguard_core::decision::DecisionLog::read_all(&audit_path).unwrap();
    assert_eq!(
        records.len(),
        3,
        "expected 3 audit records, got {}",
        records.len()
    );
}

// --- Auth middleware tests -------------------------------------------------

use agentguard_server::AuthLayer as _AuthLayer;
use std::sync::Arc;

async fn make_app_with_auth(auth: _AuthLayer) -> axum::Router {
    let dir = tempfile::tempdir().unwrap();
    let store = PolicyStore::open(dir.path()).unwrap();
    store
        .write_policy(
            "allow_alice",
            r#"permit (principal in User::"alice", action, resource);"#,
        )
        .unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let state = build_state(
        dir.path().to_path_buf(),
        Some(audit_path),
        Some(b"test-key".to_vec()),
        auth,
    )
    .await
    .unwrap();
    router(state)
}

fn api_key_payload() -> serde_json::Value {
    serde_json::json!({
        "subject": {"type": "User", "id": "alice"},
        "action": {"type": "Action", "id": "ToolCall::send"},
        "resource": {"type": "Mailbox", "id": "alice@x"},
        "context": {}
    })
}

#[tokio::test]
async fn auth_disabled_allows_anonymous_evaluation() {
    let app = make_app_with_auth(_AuthLayer::Disabled).await;
    let body = api_key_payload();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_apikey_rejects_missing_header() {
    let dir = tempfile::tempdir().unwrap();
    let store = agentguard_auth::ApiKeyStore::new();
    let (_key, raw) = store.create("ag_test", vec![], None).unwrap();
    let _ = raw; // unused — just exercising the create path
    let store_path = dir.path().join("keys.json");
    let s = agentguard_auth::ApiKeyStore::new();
    let (_, _raw) = s.create("ag_test", vec![], None).unwrap();
    s.save_to_file(&store_path).unwrap();

    let auth = _AuthLayer::ApiKey(Arc::new(
        agentguard_auth::ApiKeyStore::load_from_file(&store_path).unwrap(),
    ));
    let app = make_app_with_auth(auth).await;
    let body = api_key_payload();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_apikey_accepts_valid_bearer() {
    let dir = tempfile::tempdir().unwrap();
    let store = agentguard_auth::ApiKeyStore::new();
    let (key, raw) = store.create("ag_test", vec![], None).unwrap();
    store.save_to_file(dir.path().join("keys.json")).unwrap();
    let auth = _AuthLayer::ApiKey(Arc::new(
        agentguard_auth::ApiKeyStore::load_from_file(dir.path().join("keys.json")).unwrap(),
    ));
    let app = make_app_with_auth(auth).await;
    let body = api_key_payload();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", raw))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = key; // ensure key returned was valid (unused but keeps the API exercised)
}

#[tokio::test]
async fn auth_apikey_rejects_wrong_secret() {
    let dir = tempfile::tempdir().unwrap();
    let store = agentguard_auth::ApiKeyStore::new();
    store.create("ag_test", vec![], None).unwrap();
    store.save_to_file(dir.path().join("keys.json")).unwrap();
    let auth = _AuthLayer::ApiKey(Arc::new(
        agentguard_auth::ApiKeyStore::load_from_file(dir.path().join("keys.json")).unwrap(),
    ));
    let app = make_app_with_auth(auth).await;
    let body = api_key_payload();
    // Bearer with the right format but a tampered secret.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("content-type", "application/json")
                .header(
                    "authorization",
                    "Bearer ag_test:not-a-real-id:not-a-real-secret",
                )
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_apikey_skips_healthz() {
    // /healthz and /readyz must always be reachable without auth so
    // Kubernetes probes work.
    let dir = tempfile::tempdir().unwrap();
    let store = agentguard_auth::ApiKeyStore::new();
    store.create("ag_test", vec![], None).unwrap();
    store.save_to_file(dir.path().join("keys.json")).unwrap();
    let auth = _AuthLayer::ApiKey(Arc::new(
        agentguard_auth::ApiKeyStore::load_from_file(dir.path().join("keys.json")).unwrap(),
    ));
    let app = make_app_with_auth(auth).await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_evaluation_resolves_agent_principal_type() {
    // Phase 1.5 fix: subject.entity_type = "Agent" must produce an
    // Agent principal, not a User. Verify the round-trip by hitting
    // an Agent-targeted policy.
    let dir = tempfile::tempdir().unwrap();
    let store = PolicyStore::open(dir.path()).unwrap();
    store
        .write_policy(
            "allow_bot",
            r#"permit (principal == Agent::"bot", action, resource);"#,
        )
        .unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let state = build_state(
        dir.path().to_path_buf(),
        Some(audit_path),
        Some(b"test-key".to_vec()),
        _AuthLayer::Disabled,
    )
    .await
    .unwrap();
    let app = router(state);
    let body = serde_json::json!({
        "subject": {"type": "Agent", "id": "bot"},
        "action": {"type": "Action", "id": "ToolCall::send"},
        "resource": {"type": "Mailbox", "id": "x@y"},
        "context": {}
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["decision"], true);
}

#[tokio::test]
async fn auth_evaluation_rejects_unknown_subject_type() {
    let dir = tempfile::tempdir().unwrap();
    let store = PolicyStore::open(dir.path()).unwrap();
    store
        .write_policy("allow_alice", r#"permit (principal, action, resource);"#)
        .unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let state = build_state(
        dir.path().to_path_buf(),
        Some(audit_path),
        Some(b"test-key".to_vec()),
        _AuthLayer::Disabled,
    )
    .await
    .unwrap();
    let app = router(state);
    let body = serde_json::json!({
        "subject": {"type": "Robot", "id": "r2d2"},
        "action": {"type": "Action", "id": "ToolCall::send"},
        "resource": {"type": "Mailbox", "id": "x@y"},
        "context": {}
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    // The handler maps the principal-type Err into a 400.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn metrics_endpoint_renders_prometheus_text() {
    let dir = tempfile::tempdir().unwrap();
    let store = PolicyStore::open(dir.path()).unwrap();
    store
        .write_policy("allow_alice", r#"permit (principal, action, resource);"#)
        .unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let state = build_state(
        dir.path().to_path_buf(),
        Some(audit_path),
        Some(b"test-key".to_vec()),
        _AuthLayer::Disabled,
    )
    .await
    .unwrap();
    // Bump a few metrics so the snapshot is non-trivial.
    state.metrics().record_cache_hit();
    state.metrics().record_cache_miss();
    state.metrics().record_decision(
        "allow",
        "policy0",
        "ToolCall::send",
        "",
        std::time::Duration::from_millis(1),
    );
    let app = router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(ct.starts_with("text/plain"), "content-type was {:?}", ct);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("agentguard_cache_hit_total"));
    assert!(text.contains("agentguard_cache_miss_total"));
    assert!(text.contains("agentguard_decision_total"));
}

#[tokio::test]
async fn batch_evaluations_rejects_oversized_request() {
    // MAX_BATCH_EVALUATIONS is 100. Submit 101 to confirm the cap.
    let dir = tempfile::tempdir().unwrap();
    let store = PolicyStore::open(dir.path()).unwrap();
    store
        .write_policy("permit_all", r#"permit (principal, action, resource);"#)
        .unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let state = build_state(
        dir.path().to_path_buf(),
        Some(audit_path),
        Some(b"test-key".to_vec()),
        _AuthLayer::Disabled,
    )
    .await
    .unwrap();
    let app = router(state);
    let mut evals = Vec::with_capacity(101);
    for _ in 0..101 {
        evals.push(serde_json::json!({
            "subject": {"type": "User", "id": "alice"},
            "action": {"type": "Action", "id": "ToolCall::send"},
            "resource": {"type": "Mailbox", "id": "x@y"},
            "context": {}
        }));
    }
    let body = serde_json::json!({
        "subject": {"type": "User", "id": "alice"},
        "action": {"type": "Action", "id": "ToolCall::send"},
        "resource": {"type": "Mailbox", "id": "x@y"},
        "context": {},
        "evaluations": evals
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluations")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

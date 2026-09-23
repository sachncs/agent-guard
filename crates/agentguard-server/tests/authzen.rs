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

async fn api_key_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

async fn make_app() -> axum::Router {
    let dir = std::sync::Arc::new(tempfile::tempdir().unwrap());
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
    // Keep policy/audit files available for the router lifetime; deleting the
    // temp directory while the server holds file handles is not durable storage.
    let state: AppState = build_state(
        dir.path().to_path_buf(),
        Some(audit_path),
        Some(b"test-key".to_vec()),
        AuthLayer::Disabled,
    )
    .await
    .unwrap();
    drop(audit); // state owns its own copy via Arc.
    router(state).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let _keep_tempdir_alive = dir.clone();
            async move { next.run(request).await }
        },
    ))
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
    // Other integration tests intentionally saturate the shared process-wide
    // PDP work limiter. Retry only its explicit fail-fast response so this
    // functional assertion tests entity evaluation, not test scheduling.
    let mut resp = None;
    for attempt in 0..10 {
        let result = app
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
        if result.status() != StatusCode::SERVICE_UNAVAILABLE || attempt == 9 {
            resp = Some(result);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let resp = resp.expect("evaluation should either finish or exhaust saturation retries");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["decision"], true);
}

#[tokio::test]
async fn documented_starter_schema_request_evaluates_over_http() {
    let dir = tempfile::tempdir().unwrap();
    agentguard_core::init_store(dir.path()).unwrap();
    let store = PolicyStore::open(dir.path()).unwrap();
    store
        .write_policy(
            "allow_research_repo_read",
            r#"permit (principal == Agent::"research", action == Action::"ToolCall::repo_read", resource == Repository::"demo");"#,
        )
        .unwrap();
    let audit_path = dir.path().join(".audit/decisions.jsonl");
    let state = build_state(
        dir.path().to_path_buf(),
        Some(audit_path),
        Some(b"test-chain-secret".to_vec()),
        AuthLayer::Disabled,
    )
    .await
    .unwrap();
    let app = router(state);
    let body = serde_json::json!({
        "subject": {"type": "Agent", "id": "research"},
        "action": {"type": "Action", "id": "ToolCall::repo_read"},
        "resource": {"type": "Repository", "id": "demo"},
        "context": {"repo": "demo", "session": {"ip": "127.0.0.1"}}
    });
    let response = app
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
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["decision"], true);
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
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
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
async fn malformed_request_entities_are_rejected_as_bad_request() {
    let app = make_app_shared().await;
    let body = serde_json::json!({
        "subject": {"type": "User", "id": "alice"},
        "action": {"type": "Action", "id": "ToolCall::read"},
        "resource": {"type": "Document", "id": "doc"},
        "context": {},
        "entities": [{"uid": "not-an-entity-uid"}]
    });
    let response = app
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
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
    let dir = std::sync::Arc::new(tempfile::tempdir().unwrap());
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
    router(state).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let _keep_tempdir_alive = dir.clone();
            async move { next.run(request).await }
        },
    ))
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
    let _guard = api_key_test_guard().await;
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
    let _guard = api_key_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let store = agentguard_auth::ApiKeyStore::new();
    let identity = agentguard_auth::ApiKeyIdentity::new("User", "alice", None).unwrap();
    let (_key, raw) = store
        .create_bound("ag_test", vec!["authorize".into()], None, identity)
        .unwrap();
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
}

#[tokio::test]
async fn standalone_auth_watcher_applies_key_revocation_without_restart() {
    let _guard = api_key_test_guard().await;
    use agentguard_server::auth_layer::AuthenticationFailure;
    use agentguard_server::listener::AuthConfig;
    use agentguard_server::server::spawn_api_key_watcher;

    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("keys.json");
    let provisioner = agentguard_auth::ApiKeyStore::new();
    let (key, raw) = provisioner
        .create_bound(
            "ag_test",
            vec!["authorize".into()],
            None,
            agentguard_auth::ApiKeyIdentity::new("User", "alice", None).unwrap(),
        )
        .unwrap();
    provisioner.save_to_file(&key_path).unwrap();
    let auth = _AuthLayer::from_config(
        &AuthConfig::ApiKey {
            path: key_path.clone(),
        },
        false,
    )
    .unwrap();
    auth.authenticate_bearer(Some(&format!("Bearer {raw}")), "authorize", true)
        .unwrap();

    let (watched_path, watched_store) = auth.reloadable_key_store().unwrap();
    let watcher = spawn_api_key_watcher(watched_path, watched_store);
    let updated = agentguard_auth::ApiKeyStore::load_from_file(&key_path).unwrap();
    updated.revoke(&key.id).unwrap();
    updated.save_to_file(&key_path).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(4), async {
        loop {
            if matches!(
                auth.authenticate_bearer(Some(&format!("Bearer {raw}")), "authorize", true),
                Err(AuthenticationFailure::Unauthenticated)
            ) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("revocation should become active without restarting the PDP");
    watcher.abort();
}

#[tokio::test]
async fn auth_apikey_rejects_subject_impersonation_and_missing_scope() {
    let _guard = api_key_test_guard().await;
    let dir = tempfile::tempdir().unwrap();
    let store = agentguard_auth::ApiKeyStore::new();
    let identity = agentguard_auth::ApiKeyIdentity::new("User", "alice", None).unwrap();
    let (_, raw) = store
        .create_bound("ag_test", vec!["metrics:read".into()], None, identity)
        .unwrap();
    store.save_to_file(dir.path().join("keys.json")).unwrap();
    let auth = _AuthLayer::ApiKey(Arc::new(
        agentguard_auth::ApiKeyStore::load_from_file(dir.path().join("keys.json")).unwrap(),
    ));
    let app = make_app_with_auth(auth).await;
    let body = api_key_payload();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {raw}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let mut impersonated = api_key_payload();
    impersonated["subject"]["id"] = serde_json::json!("mallory");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/access/v1/evaluation")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {raw}"))
                .body(Body::from(serde_json::to_vec(&impersonated).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn auth_apikey_rejects_wrong_secret() {
    let _guard = api_key_test_guard().await;
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
    assert!(matches!(
        resp.status(),
        StatusCode::UNAUTHORIZED | StatusCode::SERVICE_UNAVAILABLE
    ));
}

#[tokio::test]
async fn auth_apikey_skips_healthz() {
    let _guard = api_key_test_guard().await;
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
async fn audit_open_failure_fails_startup() {
    // A special audit destination must be rejected before the server can
    // become ready. A device symlink is deterministic even when the test
    // process runs as root, which can bypass ordinary permission bits.
    let dir = tempfile::tempdir().unwrap();
    let store = PolicyStore::open(dir.path()).unwrap();
    store
        .write_policy("allow_alice", r#"permit (principal, action, resource);"#)
        .unwrap();
    #[cfg(unix)]
    {
        let full = std::path::Path::new("/dev/full");
        if !full.exists() {
            return;
        }
        let audit_path = dir.path().join("audit.jsonl");
        std::os::unix::fs::symlink(full, &audit_path).unwrap();
        let result = build_state(
            dir.path().to_path_buf(),
            Some(audit_path),
            Some(b"test-key".to_vec()),
            _AuthLayer::Disabled,
        )
        .await;
        let error = result
            .err()
            .expect("build_state must reject non-regular audit storage");
        assert!(error.contains("regular file"), "unexpected error: {error}");
    }
    #[cfg(not(unix))]
    {
        // Non-Unix: the OS-level permission semantics differ;
        // CI on Ubuntu exercises this path.
    }
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

#[tokio::test]
async fn batch_evaluation_uses_each_item_entity_set() {
    let dir = tempfile::tempdir().unwrap();
    let store = PolicyStore::open(dir.path()).unwrap();
    store
        .write_policy(
            "verified_only",
            r#"permit (principal, action, resource) when { principal.verified == true };"#,
        )
        .unwrap();
    let state = build_state(
        dir.path().to_path_buf(),
        Some(dir.path().join("audit.jsonl")),
        Some(b"test-key".to_vec()),
        _AuthLayer::Disabled,
    )
    .await
    .unwrap();
    let app = router(state);
    let request = |entities: serde_json::Value| {
        serde_json::json!({
            "subject": {"type": "User", "id": "carol"},
            "action": {"type": "Action", "id": "ToolCall::read"},
            "resource": {"type": "Document", "id": "doc-1"},
            "context": {},
            "entities": entities
        })
    };
    let body = serde_json::json!({
        "evaluations": [
            request(serde_json::json!([{"uid":{"type":"User","id":"carol"},"attrs":{"verified":true},"parents":[]}])),
            request(serde_json::json!([]))
        ]
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
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["evaluations"][0]["decision"], true);
    assert_eq!(value["evaluations"][1]["decision"], false);
}

#[tokio::test]
async fn evaluation_preserves_context_key_named_trace() {
    // Regression: the AuthZEN bridge used to silently drop any
    // context key named "trace". Forward it as a regular argument
    // so callers can attach observability data without losing it.
    use agentguard_server::evaluation_request_to_agent;
    let req: agentguard_server::authzen::EvaluationRequest =
        serde_json::from_value(serde_json::json!({
            "subject": {"type": "User", "id": "alice"},
            "action": {"type": "Action", "id": "ToolCall::send"},
            "resource": {"type": "Mailbox", "id": "alice@x"},
            "context": {
                "trace": {"span_id": "abc-123", "parent": "root"},
                "to": "[email protected]"
            }
        }))
        .unwrap();
    let agent_req = evaluation_request_to_agent(req).unwrap();
    let trace_value = agent_req.context.args.get("trace");
    assert!(
        trace_value.is_some(),
        "context.trace must be preserved, got {:?}",
        agent_req.context.args
    );
    assert_eq!(trace_value.unwrap()["span_id"], "abc-123");
}

#[test]
fn bound_tenant_is_trusted_audit_metadata_not_caller_context() {
    use agentguard_server::auth_layer::AuthenticatedIdentity;
    use agentguard_server::authzen::{
        evaluation_request_for_caller, EntityRef, EvaluationMappingError, EvaluationRequest,
    };

    let caller = AuthenticatedIdentity {
        identity: agentguard_auth::ApiKeyIdentity::new("User", "alice", Some("tenant-a".into()))
            .unwrap(),
        can_act_as: false,
    };
    let request = EvaluationRequest {
        subject: EntityRef {
            entity_type: "User".into(),
            id: "alice".into(),
        },
        action: EntityRef {
            entity_type: "Action".into(),
            id: "read".into(),
        },
        resource: EntityRef {
            entity_type: "Document".into(),
            id: "doc-1".into(),
        },
        context: serde_json::json!({"tenant_id":"tenant-a", "purpose":"review"}),
        entities: vec![],
    };
    let mapped = evaluation_request_for_caller(request, Some(&caller)).unwrap();
    assert_eq!(mapped.tenant_id.as_deref(), Some("tenant-a"));
    assert_eq!(mapped.context.args.get("tenant_id"), None);
    assert_eq!(mapped.context.args["purpose"], "review");

    let conflicting = EvaluationRequest {
        subject: EntityRef {
            entity_type: "User".into(),
            id: "alice".into(),
        },
        action: EntityRef {
            entity_type: "Action".into(),
            id: "read".into(),
        },
        resource: EntityRef {
            entity_type: "Document".into(),
            id: "doc-1".into(),
        },
        context: serde_json::json!({"tenant_id":"tenant-b"}),
        entities: vec![],
    };
    assert!(matches!(
        evaluation_request_for_caller(conflicting, Some(&caller)),
        Err(EvaluationMappingError::IdentityMismatch)
    ));
}

#[test]
fn act_as_scope_allows_console_simulation_but_keeps_key_tenant_trusted() {
    use agentguard_server::auth_layer::AuthenticatedIdentity;
    use agentguard_server::authzen::{evaluation_request_for_caller, EntityRef, EvaluationRequest};

    let caller = AuthenticatedIdentity {
        identity: agentguard_auth::ApiKeyIdentity::new(
            "Agent",
            "console-service",
            Some("tenant-a".into()),
        )
        .unwrap(),
        can_act_as: true,
    };
    let request = EvaluationRequest {
        subject: EntityRef {
            entity_type: "Agent".into(),
            id: "research-agent".into(),
        },
        action: EntityRef {
            entity_type: "Action".into(),
            id: "read".into(),
        },
        resource: EntityRef {
            entity_type: "Document".into(),
            id: "doc-1".into(),
        },
        context: serde_json::json!({"tenant_id":"tenant-a", "purpose":"review"}),
        entities: vec![],
    };
    let mapped = evaluation_request_for_caller(request, Some(&caller)).unwrap();
    assert_eq!(mapped.principal.to_string(), "Agent::\"research-agent\"");
    assert_eq!(mapped.tenant_id.as_deref(), Some("tenant-a"));
    assert_eq!(mapped.context.args.get("tenant_id"), None);
    assert_eq!(mapped.context.args["purpose"], "review");
}

//! Integration tests for the AuthZEN HTTP server.
//!
//! Uses `axum::Router::oneshot` for in-process HTTP testing without binding to
//! a real port. Catches regressions in middleware, body limits, request ID
//! tracing, and handler routing.

use agentguard_core::PolicyStore;
use agentguard_server::authzen::{build_state, router};
use agentguard_server::AppState;
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
    let state: AppState =
        build_state(dir.path().to_path_buf(), Some(audit_path), Some(b"test-key".to_vec()))
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

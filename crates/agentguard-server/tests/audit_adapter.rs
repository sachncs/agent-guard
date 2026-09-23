use agentguard_core::{Decision, PolicyStore};
use agentguard_server::authzen::{build_state, router};
use agentguard_server::{AsyncAuditAppender, AuditAppender, AuthLayer};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

#[derive(Default)]
struct TestAuditStore(AtomicUsize);

impl AuditAppender for TestAuditStore {
    fn append_decision(&self, _decision: &Decision) -> agentguard_core::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn is_healthy(&self) -> bool {
        true
    }

    fn is_chained(&self) -> bool {
        true
    }
}

#[derive(Default)]
struct TestAsyncAuditStore(AtomicUsize);

#[async_trait::async_trait]
impl AsyncAuditAppender for TestAsyncAuditStore {
    async fn append_decision(&self, _decision: &Decision) -> agentguard_core::Result<()> {
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn is_healthy(&self) -> bool {
        true
    }

    async fn is_chained(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn embedded_pdp_can_use_an_external_durable_audit_adapter() {
    let dir = tempfile::tempdir().unwrap();
    let policies = PolicyStore::open(dir.path()).unwrap();
    policies
        .write_policy("allow", "permit(principal, action, resource);")
        .unwrap();

    let audit = Arc::new(TestAuditStore::default());
    let state = build_state(dir.path().to_path_buf(), None, None, AuthLayer::Disabled)
        .await
        .unwrap()
        .with_audit_appender(audit.clone());
    let app = router(state);

    let ready = app
        .clone()
        .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::OK);

    let response = app
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

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(audit.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn async_audit_adapter_is_awaited_without_blocking_runtime_workers() {
    let dir = tempfile::tempdir().unwrap();
    let policies = PolicyStore::open(dir.path()).unwrap();
    policies
        .write_policy("allow", "permit(principal, action, resource);")
        .unwrap();

    let audit = Arc::new(TestAsyncAuditStore::default());
    let state = build_state(dir.path().to_path_buf(), None, None, AuthLayer::Disabled)
        .await
        .unwrap()
        .with_async_audit_appender(audit.clone());
    let app = router(state);
    let ticks = Arc::new(AtomicUsize::new(0));
    let tick_count = ticks.clone();
    let ticker = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(10));
        loop {
            interval.tick().await;
            tick_count.fetch_add(1, Ordering::Relaxed);
        }
    });

    let response = app
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
    ticker.abort();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(audit.0.load(Ordering::SeqCst), 1);
    assert!(
        ticks.load(Ordering::Relaxed) >= 3,
        "Tokio tasks should progress during async audit persistence"
    );
}

struct StalledHealthAuditStore;

#[async_trait::async_trait]
impl AsyncAuditAppender for StalledHealthAuditStore {
    async fn append_decision(&self, _decision: &Decision) -> agentguard_core::Result<()> {
        Ok(())
    }

    async fn is_healthy(&self) -> bool {
        std::future::pending().await
    }

    async fn is_chained(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn readiness_fails_closed_when_async_audit_health_check_stalls() {
    let dir = tempfile::tempdir().unwrap();
    let policies = PolicyStore::open(dir.path()).unwrap();
    policies
        .write_policy("allow", "permit(principal, action, resource);")
        .unwrap();
    let state = build_state(dir.path().to_path_buf(), None, None, AuthLayer::Disabled)
        .await
        .unwrap()
        .with_async_audit_appender(Arc::new(StalledHealthAuditStore));

    let response = router(state)
        .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

struct FailingAsyncAuditStore;

#[async_trait::async_trait]
impl AsyncAuditAppender for FailingAsyncAuditStore {
    async fn append_decision(&self, _decision: &Decision) -> agentguard_core::Result<()> {
        Err(agentguard_core::Error::Io(
            "audit backend unavailable".into(),
        ))
    }

    async fn is_healthy(&self) -> bool {
        false
    }

    async fn is_chained(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn async_audit_append_failure_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let policies = PolicyStore::open(dir.path()).unwrap();
    policies
        .write_policy("allow", "permit(principal, action, resource);")
        .unwrap();
    let state = build_state(dir.path().to_path_buf(), None, None, AuthLayer::Disabled)
        .await
        .unwrap()
        .with_async_audit_appender(Arc::new(FailingAsyncAuditStore));

    let response = router(state)
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
}

struct StalledAppendAuditStore;

#[async_trait::async_trait]
impl AsyncAuditAppender for StalledAppendAuditStore {
    async fn append_decision(&self, _decision: &Decision) -> agentguard_core::Result<()> {
        std::future::pending().await
    }

    async fn is_healthy(&self) -> bool {
        true
    }

    async fn is_chained(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn stalled_async_audit_append_times_out_and_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let policies = PolicyStore::open(dir.path()).unwrap();
    policies
        .write_policy("allow", "permit(principal, action, resource);")
        .unwrap();
    let state = build_state(dir.path().to_path_buf(), None, None, AuthLayer::Disabled)
        .await
        .unwrap()
        .with_async_audit_appender(Arc::new(StalledAppendAuditStore));

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(6),
        router(state).oneshot(
            Request::post("/access/v1/evaluation")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"subject":{"type":"User","id":"alice"},"action":{"type":"Action","id":"read"},"resource":{"type":"Document","id":"doc"},"context":{}}"#,
                ))
                .unwrap(),
        ),
    )
    .await
    .expect("bounded audit timeout should complete the request")
    .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

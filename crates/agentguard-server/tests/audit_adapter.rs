use agentguard_core::{Decision, PolicyStore};
use agentguard_server::authzen::{build_state, router};
use agentguard_server::{AuditAppender, AuthLayer};
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

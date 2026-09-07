use agentguard_core::PolicyStore;
use agentguard_server::authzen::build_state;
use agentguard_server::grpc::service;
use agentguard_server::proto::agentguard::v1::{
    access_evaluation_client::AccessEvaluationClient, EntityRef, EvaluationRequest,
};
use agentguard_server::AuthLayer;
use std::sync::Arc;

#[tokio::test]
async fn grpc_evaluation_returns_decision() {
    let dir = tempfile::tempdir().unwrap();
    let store = PolicyStore::open(dir.path()).unwrap();
    store
        .write_policy(
            "allow_alice",
            r#"permit (principal == User::"alice", action, resource);"#,
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
    let svc = service(Arc::new(state));
    // Spin up a tonic server on a random port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(svc)
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    let mut client = AccessEvaluationClient::connect(format!("http://{}", addr))
        .await
        .unwrap();
    let req = EvaluationRequest {
        subject: Some(EntityRef {
            r#type: "User".into(),
            id: "alice".into(),
        }),
        action: Some(EntityRef {
            r#type: "Action".into(),
            id: "ToolCall::send".into(),
        }),
        resource: Some(EntityRef {
            r#type: "Mailbox".into(),
            id: "alice@x".into(),
        }),
        context_json: "{}".into(),
        entities_json: "[]".into(),
    };
    let resp = client.evaluation(req).await.unwrap();
    assert!(resp.into_inner().decision);
}

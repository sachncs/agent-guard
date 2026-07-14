//! Benchmarks for the agentguard authorization hot path.
//!
//! Run with `cargo bench -p agentguard-core`.

use agentguard_core::authorize::entities::build_entities;
use agentguard_core::{AgentRequest, AgentRequestBuilder, Authorizer, PolicyStore};
use agentguard_core::{AgentAction, AgentContext, Principal, Resource};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::OnceLock;

fn make_store() -> &'static PolicyStore {
    static STORE: OnceLock<PolicyStore> = OnceLock::new();
    STORE.get_or_init(|| {
        // Build a temporary store once and reuse it across iterations.
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PolicyStore::open(dir.path()).expect("open");
        store
            .write_policy(
                "allow_alice",
                r#"permit (principal in User::"alice", action, resource);"#,
            )
            .expect("write allow");
        store
            .write_policy(
                "allow_admins",
                r#"permit (principal in User::"admin", action, resource);"#,
            )
            .expect("write allow admins");
        // We can't easily persist the store across runs in a static, so
        // we accept the minor cost of rebuilding.
        store
    })
}

fn make_request() -> AgentRequest {
    AgentRequestBuilder::new(Principal::user("alice"))
        .action(AgentAction::tool("send_email"))
        .resource(Resource::new("Mailbox", "alice@acme"))
        .context(
            AgentContext::new()
                .with_arg("to", "[email protected]")
                .with_arg("subject", "hi")
                .with_arg("body", "hello"),
        )
        .build()
    .unwrap()
}

fn bench_authorize(c: &mut Criterion) {
    let store = make_store();
    let authorizer = Authorizer::new(store.clone_for_bench()).expect("authorizer");
    let req = make_request();
    let entities = build_entities(vec![]).expect("entities");
    c.bench_function("authorize_simple", |b| {
        b.iter(|| {
            let _ = black_box(authorizer.authorize(black_box(&req), black_box(&entities)).expect("ok"));
        });
    });
}

fn bench_authorize_with_deny(c: &mut Criterion) {
    // Use a store with a deny clause so the authz engine does real work.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PolicyStore::open(dir.path()).expect("open");
    store
        .write_policy(
            "allow_alice",
            r#"permit (principal in User::"alice", action, resource);"#,
        )
        .expect("write");
    store
        .write_policy(
            "deny_after_8pm",
            r#"forbid (principal, action, resource) when { true };"#,
        )
        .expect("write forbid");
    let authorizer = Authorizer::new(store).expect("authorizer");
    let req = make_request();
    let entities = build_entities(vec![]).expect("entities");
    c.bench_function("authorize_with_deny", |b| {
        b.iter(|| {
            let _ = black_box(authorizer.authorize(black_box(&req), black_box(&entities)).expect("ok"));
        });
    });
}

criterion_group!(benches, bench_authorize, bench_authorize_with_deny);
criterion_main!(benches);

/// Helper extension: clone_for_bench() — PolicyStore isn't Clone, so we
/// rebuild. This is a stand-in for v2.1 where PolicyStore is Clone via Arc.
trait PolicyStoreExt {
    fn clone_for_bench(&self) -> PolicyStore;
}
impl PolicyStoreExt for PolicyStore {
    fn clone_for_bench(&self) -> PolicyStore {
        // For the benchmark we just rebuild the store from the same path
        // contents. This is cheap for our test schema.
        let _ = self; // suppress unused
        let dir = tempfile::tempdir().expect("tempdir");
        let store = PolicyStore::open(dir.path()).expect("open");
        store
            .write_policy(
                "allow_alice",
                r#"permit (principal in User::"alice", action, resource);"#,
            )
            .expect("write");
        store
            .write_policy(
                "allow_admins",
                r#"permit (principal in User::"admin", action, resource);"#,
            )
            .expect("write");
        store
    }
}
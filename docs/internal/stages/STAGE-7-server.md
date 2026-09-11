# Stage 7 — Server crate (AuthZEN HTTP + gRPC sidecar)

**Goal:** Run agentguard as a remote PDP. AuthZEN-compatible HTTP endpoints +
gRPC service. Sidecar deployment via Unix socket.

**Pre-flight:** Stage 6 complete. Policy operations + cache + auth all working.

## Todos

### 7.1 — Crate setup
- [ ] `crates/agentguard-server/Cargo.toml`:
  - Dependencies: `axum`, `tower`, `tower-http` (tracing, cors), `tonic`, `prost`, `hyper`
  - `serde_json`, `tokio`, `async-trait`, `tracing`, `anyhow`
  - Workspace deps: `agentguard-core`, `agentguard-policy`, `agentguard-auth`, `agentguard-telemetry`
  - Build deps: `tonic-build`, `prost-build`
- [ ] `src/main.rs`: `agentguard serve` binary entry point

### 7.2 — Proto schema
- [ ] `proto/pdp.proto`:
  ```protobuf
  syntax = "proto3";
  package agentguard.v1;

  service Pdp {
    rpc Evaluate(EvaluationRequest) returns (EvaluationResponse);
    rpc Evaluations(BatchEvaluationRequest) returns (BatchEvaluationResponse);
  }

  message EvaluationRequest {
    string subject_type = 1;
    string subject_id = 2;
    string action = 3;
    string resource_type = 4;
    string resource_id = 5;
    map<string, Value> context = 6;
  }

  message EvaluationResponse {
    bool decision = 1;
    map<string, Value> context = 2;
    string reason = 3;
  }
  ```
- [ ] `build.rs` invokes `tonic_build::compile_protos("proto/pdp.proto")`
- [ ] Generated code in `OUT_DIR`

### 7.3 — HTTP server (AuthZEN-compatible)
- [ ] `src/http.rs`:
  - Axum router
  - Routes:
    - `POST /access/v1/evaluation`
    - `POST /access/v1/evaluations`
    - `GET /healthz`
    - `GET /readyz`
    - `GET /metrics`
- [ ] `src/authzen.rs`:
  - Request type: `AuthZenEvaluationRequest { subject: EntityRef, action: EntityRef, resource: EntityRef, context: serde_json::Value }`
  - Response type: `AuthZenEvaluationResponse { decision: bool, context: serde_json::Value, reason: Option<String> }`
  - `EvaluationSemantics { ExecuteAll, DenyOnFirstDeny, PermitOnFirstPermit }`
  - Batch: `AuthZenEvaluationsRequest { evaluations: Vec<AuthZenEvaluationRequest>, semantics: EvaluationSemantics, subject: Option<EntityRef> }`
- [ ] Handler: convert AuthZen → AgentRequest → authorize → AuthZen response
- [ ] JSON serialization matches AuthZEN WG draft (snake_case, decision bool)
- [ ] Test: `authzen_evaluation_endpoint_returns_correct_decision`

### 7.4 — gRPC server
- [ ] `src/grpc.rs`:
  - Tonic service impl on `agentguard::v1::pdp_server::Pdp`
  - Implements `evaluate()` and `evaluations()`
  - Test: gRPC client/server integration test (in-process channel)

### 7.5 — Authentication on the wire
- [ ] `src/auth_layer.rs`:
  - Axum middleware that authenticates each request via `Authenticator`
  - Bearer JWT (validated against OIDC)
  - DPoP-bound JWT
  - mTLS (requires rustls + cert extraction)
  - API key (in Authorization header as `Bearer <key>`)
- [ ] Authenticated principal is attached to request extensions for downstream handlers
- [ ] `agentguard serve --auth jwt=https://idp.example.com --auth api-keys=./keys.json`
- [ ] Test: `http_server_rejects_unauthenticated_request`

### 7.6 — Listener
- [ ] `src/listener.rs`:
  - `pub enum Listener { Tcp(SocketAddr), Unix(PathBuf), Tls(SocketAddr, TlsConfig) }`
  - `pub fn bind(listener: Listener) -> Result<Server, ServerError>`
  - Unix socket support uses `tokio::net::UnixListener`
  - TLS uses `axum-server` with rustls
- [ ] `agentguard serve --listen tcp://0.0.0.0:8443 --tls-cert ./server.pem --tls-key ./server.key`
- [ ] `agentguard serve --listen unix:///var/run/agentguard.sock` (sidecar mode)
- [ ] Test: bind/listen works for each variant

### 7.7 — Health endpoints
- [ ] `GET /healthz` — always returns 200 if process is alive
- [ ] `GET /readyz` — returns 200 only if: policies loaded, auth configured, telemetry exporting (or gracefully degraded)
- [ ] Returns JSON: `{ "status": "ok", "checks": { "policies": "ok", "auth": "ok" } }`
- [ ] Test: `healthz_always_ok`, `readyz_fails_when_not_configured`

### 7.8 — Metrics endpoint
- [ ] `GET /metrics` — Prometheus text format
- [ ] Uses `agentguard-telemetry::Metrics::render_prometheus()`
- [ ] Standard metrics: decision_total, decision_duration_seconds, cache_hits_total, etc.
- [ ] Test: `metrics_endpoint_returns_prometheus_format`

### 7.9 — CLI binary
- [ ] `crates/agentguard-server/src/main.rs`:
  ```rust
  #[tokio::main]
  async fn main() -> Result<()> {
      let cli = Cli::parse();
      let authorizer = Authorizer::new(...)?;
      let auth = Authenticator::builder()...build().await?;
      let listener = Listener::parse(&cli.listen)?;
      let server = Server::new(authorizer, auth, listener);
      server.serve().await
  }
  ```
- [ ] Add `agentguard-server` binary to root `Cargo.toml` members
- [ ] Test: end-to-end smoke test — start server, hit `/healthz`, fire one `/access/v1/evaluation`, hit `/metrics`

### 7.10 — Python/TS server SDK
- [ ] `python/agentguard_server_sdk/` package:
  - `client = AuthZenClient(url="http://localhost:8443", token="...")`
  - `client.evaluate(subject=..., action=..., resource=..., context=...)`
- [ ] `typescript/agentguard-server-sdk/` package: mirror
- [ ] Test: round-trip a Cedar decision via the SDK

### 7.11 — Final verification
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo doc --workspace --no-deps` no warnings
- [ ] Manual smoke test: `agentguard serve --listen tcp://127.0.0.1:8443 --store ./.agentguard` + curl to `/access/v1/evaluation`
- [ ] `/metrics` returns valid Prometheus output
- [ ] `/healthz` and `/readyz` return the expected codes

## Commit

```bash
git add -A
git commit -m "stage(7): AuthZEN HTTP + gRPC server crate (sidecar)

- New crates/agentguard-server crate with agentguard serve binary
- AuthZEN-compatible HTTP endpoints (/access/v1/evaluation, /access/v1/evaluations)
- gRPC service via tonic with EvaluationRequest/EvaluationResponse
- Auth middleware: JWT, DPoP, API key, mTLS via authenticator
- Listener: tcp, tls, unix socket (for K8s sidecar)
- Health endpoints (/healthz, /readyz) with structured check responses
- Prometheus metrics at /metrics
- Python and TypeScript server SDKs (AuthZenClient)
- Proto schema in proto/pdp.proto
- Workspace member, agentguard-server binary"
```

## Done when
- [ ] Commit landed
- [ ] Server boots, serves AuthZEN requests, returns metrics
- [ ] Python SDK can talk to the server
- [ ] Move to Stage 8

## What NOT to do
- Do not implement SDK in-process mode yet (Stage 8)
- Do not add CI workflows yet (Stage 9)
# Stage 1 — Telemetry crate

**Goal:** Pluggable observability layer. Every decision can be traced end-to-end
(W3C Trace Context), exported via OTel or to pluggable sinks.

**Pre-flight:** Stage 0 complete. `cargo test --workspace` shows 8 passing tests.

## Todos

### 1.1 — Crate setup
- [ ] `crates/agentguard-telemetry/Cargo.toml`:
  - `[features]`: `default = ["jsonl", "stdout"]`, `jsonl = [...]`, `stdout = [...]`, `otlp = ["dep:opentelemetry", "dep:opentelemetry-otlp", "dep:opentelemetry_sdk", "dep:tracing-opentelemetry"]`
  - Dependencies: `serde`, `serde_json`, `async-trait`, `chrono`, `tokio`, `tracing`, `tracing-subscriber`, `thiserror`
- [ ] `src/lib.rs`: `pub mod sink; pub mod jsonl; pub mod stdout; #[cfg(feature = "otlp")] pub mod otlp; pub mod event; pub mod metrics;`
- [ ] `src/sink.rs`: define `Sink` trait + `SinkEvent<'a>` struct carrying decision records

### 1.2 — Sink trait
- [ ] Trait:
  ```rust
  #[async_trait]
  pub trait Sink: Send + Sync {
      fn name(&self) -> &str;
      async fn emit(&self, event: &SinkEvent<'_>) -> Result<(), SinkError>;
      async fn flush(&self) -> Result<(), SinkError> { Ok(()) }
      async fn shutdown(&self) -> Result<(), SinkError> { Ok(()) }
  }
  ```
- [ ] `SinkError` enum: `Io(std::io::Error)`, `Json(serde_json::Error)`, `Send(String)`, `Other(String)`
- [ ] `SinkEvent` carries: timestamp, decision record, optional trace context, optional metric delta

### 1.3 — JSONL sink (always-on)
- [ ] Wraps the existing `DecisionLog` writer pattern
- [ ] Constructor: `JsonlSink::open(path: impl Into<PathBuf>) -> Result<Self>`
- [ ] Emits one JSON object per line with all decision record fields
- [ ] Test: `jsonl_sink_writes_valid_jsonl`

### 1.4 — Stdout sink
- [ ] `StdoutSink` prints events as pretty JSON to stdout (for debugging)
- [ ] Constructor: `StdoutSink::new()` or `StdoutSink::pretty()`
- [ ] Test: stdout sink is unit-testable with `cursor` capture

### 1.5 — OTel sink (feature-gated)
- [ ] When `otlp` feature enabled: `OtlpSink` wraps `opentelemetry-otlp` exporter
- [ ] Emits decisions as OTel log events with `authz.*` attributes
- [ ] Spans: each authorize() call wrapped in a span named `agentguard.authorize` with start/end timestamps
- [ ] Test: requires `#[cfg(feature = "otlp")]` test that uses `opentelemetry_sdk::testing`

### 1.6 — Metrics
- [ ] `src/metrics.rs` defines `Metrics` struct with atomic counters:
  - `decision_total{ effect, policy_id, action, tenant_id }` (Counter)
  - `decision_duration_seconds{ ... }` (Histogram — 8 buckets: 0.001, 0.01, 0.1, 1, 10, 100, 1000, 10000 ms)
  - `delegation_mint_total`, `delegation_verify_total{ outcome }`
  - `cache_hit_total`, `cache_miss_total`
  - `policy_reload_total`
- [ ] `Metrics::record(&self, event: &SinkEvent)` increments counters based on event type
- [ ] Export via `Metrics::render_prometheus() -> String` for `/metrics` endpoint (Stage 7)
- [ ] Test: `metrics_increment_on_allow`, `metrics_increment_on_deny`

### 1.7 — Wire into Authorizer
- [ ] `Authorizer` gains `sinks: Vec<Arc<dyn Sink>>` and `metrics: Arc<Metrics>` fields
- [ ] `Authorizer::new()` default: `sinks = vec![]`, `metrics = Arc::new(Metrics::new())`
- [ ] `Authorizer::with_sinks(sinks)` builder method
- [ ] `authorize()` emits a `SinkEvent::Decision(record, trace_ctx, duration)` to all sinks at the end
- [ ] Default to NO sinks for back-compat (v1 behavior unchanged)

### 1.8 — Wire into CLI
- [ ] `agentguard` CLI flags: `--sink jsonl=<path>`, `--sink stdout`, `--sink otlp=<endpoint>`
- [ ] Wire sinks into `Authorizer` at startup
- [ ] Existing `--audit` flag continues to work (back-compat alias for `--sink jsonl=<path>`)
- [ ] Test: CLI help text shows sink options

### 1.9 — Telemetry-enabled tests
- [ ] `telemetry::tests::jsonl_sink_captures_decision` — fire one authorization, assert JSONL file has one line
- [ ] `telemetry::tests::metrics_count_allow_and_deny` — fire 2 allows + 1 deny, assert counts
- [ ] `telemetry::tests::trace_id_propagates_through_sink` — request with trace context, sink sees same trace_id

### 1.10 — Final verification
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes (8 core + ~3-5 new telemetry tests)
- [ ] `cargo doc --workspace --no-deps` no warnings
- [ ] No new `TODO(stage-1)` comments

## Commit

```bash
git add -A
git commit -m "stage(1): telemetry crate with pluggable sinks

- New crates/agentguard-telemetry crate with Sink trait
- JSONL sink (always-on, replaces inline decision logging)
- Stdout sink for debugging
- OTel/OTLP sink behind feature flag (spans + authz.* attributes)
- Metrics counters + Prometheus render
- Authorizer accepts sinks; CLI --sink flag wires them in
- Back-compat: default behavior unchanged when no sinks configured"
```

## Done when
- [ ] Commit landed
- [ ] All telemetry tests pass
- [ ] CLI `--sink stdout` produces JSON output for one authorize call
- [ ] Move to Stage 2

## What NOT to do
- Do not implement hash chains here (Stage 2)
- Do not implement auth (Stage 3)
- Do not implement AuthZEN server (Stage 7)
- Do not break existing CLI commands
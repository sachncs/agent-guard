# Stage 0 — Style, layout, and architecture hardening

**Goal:** Clean, style-guide-compliant, modular foundation. No behavior change from
v1, just better-organized code. Everything later builds on this.

## Reference

- Rust style guide: https://doc.rust-lang.org/style-guide/
- Cargo.toml conventions: https://doc.rust-lang.org/style-guide/cargo.html

## Pre-flight (read this)

Before starting, run:
```bash
git status                     # confirm clean tree
git log --oneline -5           # see prior commits
cargo test --workspace         # confirm v1 tests pass (8 in agentguard-core)
```

If `cargo test` doesn't show 8 passing tests in `agentguard_core`, fix v1 first.

## Todos

### 0.1 — Tooling
- [ ] Add `rustfmt.toml` at repo root with: `max_width = 100`, `tab_spaces = 4`, `trailing_comma = "Vertical"`, `imports_granularity = "Crate"`, `group_imports = "StdExternalCrate"`, `reorder_imports = true`
- [ ] Add `clippy.toml` at repo root with: `avoid-breaking-exported-api = false`, `pedantic = { level = "warn", priority = -1 }`
- [ ] Verify both files: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings`
- [ ] CI workflow `.github/workflows/ci.yml` runs fmt, clippy, test (skeleton — full content in Stage 9)

### 0.2 — Workspace restructure
- [ ] Create empty crate dirs: `crates/agentguard-telemetry/`, `crates/agentguard-auth/`, `crates/agentguard-policy/`, `crates/agentguard-server/`
- [ ] Add `members = [ ... ]` entries to root `Cargo.toml`
- [ ] Each new crate has minimal `Cargo.toml` + `src/lib.rs` with `// placeholder — see stages/STAGE-N-*.md`
- [ ] Verify: `cargo build --workspace` still succeeds

### 0.3 — Style sweep across core
- [ ] Remove unused `Error::Cedar(String)` variant in `crates/agentguard-core/src/error.rs`
- [ ] Remove `ActionDef` empty struct in `crates/agentguard-core/src/request.rs`
- [ ] Remove `KeyBundle` struct in `crates/agentguard-core/src/delegation.rs` (it's unused)
- [ ] Remove `_schema_anchor` no-op in `crates/agentguard-cli/src/commands/gen.rs`
- [ ] Remove unused `path: PathBuf` field in `crates/agentguard-core/src/decision.rs::DecisionLog` (use `#[allow(dead_code)]` if needed)
- [ ] Remove stale comments: `// Build context JSON.` and `// Add session metadata at top level for convenience.` in `request.rs::to_cedar_request`
- [ ] Run `cargo fmt --all` and `cargo clippy --workspace --all-targets --fix --allow-dirty --allow-no-vcs`

### 0.4 — Module split (request.rs → 5 files)
- [ ] Create `crates/agentguard-core/src/ids.rs` with:
  - `PrincipalId(pub String)`, `ActionId(pub String)`, `ResourceId(pub String)`
  - All implement `Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Deref<Target=str>`, `Display`
  - `impl From<&str> for PrincipalId` etc.
- [ ] Create `crates/agentguard-core/src/principal.rs` with `Principal` enum (moved from `request.rs`)
- [ ] Create `crates/agentguard-core/src/action.rs` with `AgentAction` (moved from `request.rs`)
- [ ] Create `crates/agentguard-core/src/resource.rs` with `Resource` (moved from `request.rs`)
- [ ] Create `crates/agentguard-core/src/context.rs` with `AgentContext` (moved from `request.rs`)
- [ ] `crates/agentguard-core/src/request.rs` now contains only `AgentRequest` + `AgentRequestBuilder`
- [ ] Update `lib.rs` re-exports
- [ ] Update all `use crate::request::Principal` → `use crate::principal::Principal` across the workspace
- [ ] Verify: `cargo test --workspace` passes (8 tests in core)

### 0.5 — TTL primitives
- [ ] Create `crates/agentguard-core/src/ttl.rs` with:
  - `pub trait Clock: Send + Sync { fn now(&self) -> Instant; fn unix_now(&self) -> i64; }`
  - `pub struct SystemClock;` impl `Clock`
  - `pub struct MockClock { inner: Mutex<Instant> }` impl `Clock` (used in tests later)
  - `pub type Timestamp = i64;` (Unix seconds; alias kept for clarity)
- [ ] Add `clock: Arc<dyn Clock>` field to `Authorizer` with default `Arc::new(SystemClock)`
- [ ] Verify: `cargo test --workspace` passes

### 0.6 — Typed time + ids in delegation
- [ ] Change `DelegationConfig.ttl_seconds: i64` → `DelegationConfig.ttl: Duration`
- [ ] Add `DelegationConfig::default()` returning `Duration::from_secs(900)`
- [ ] Use `Duration` in `mint_with` for `exp - iat`
- [ ] In `CLI`, change `--ttl` to accept a humantime string (e.g. `15m`, `2h`, `900s`) — use the `humantime` crate
- [ ] Verify: `cargo test --workspace` passes

### 0.7 — Request ID + trace context
- [ ] Add `uuid` feature `v7` (already enabled) — confirm
- [ ] `AgentRequest::new()` auto-fills `request_id: Uuid::now_v7()` if not provided
- [ ] Add `trace: Option<TraceContext>` field to `AgentRequest`
- [ ] `TraceContext { trace_id: TraceId(128-bit), span_id: SpanId(64-bit), parent_span_id: Option<SpanId>, tracestate: Option<String> }` — newtypes wrapping `[u8; 16]` and `[u8; 8]`
- [ ] Implement `FromStr` for `TraceContext` parsing W3C `traceparent` header (`00-<trace_id>-<span_id>-<flags>`)
- [ ] `impl Display for TraceContext` emitting the `traceparent` string
- [ ] `DecisionRecord` gains `trace_id: Option<TraceId>`, `span_id: Option<SpanId>` fields
- [ ] `DecisionRecord::from_decision` extracts trace context from the embedded request JSON
- [ ] Test: `request_id_uniqueness` and `traceparent_roundtrip`
- [ ] Verify: `cargo test --workspace` passes

### 0.8 — Per-policy effects surfaced
- [ ] `Decision` gains `policy_effects: Vec<PolicyEffect>` field (skipped in serde if empty)
- [ ] `PolicyEffect { policy_id: String, effect: Effect }` struct
- [ ] `authorize()` populates from `CedarResponse` (which exposes per-policy effects)
- [ ] Investigate cedar-policy 4.x API for `effects_per_policy()` — if unavailable, fall back to deriving from `diagnostics().reason()` (which lists determining policies) and label them `Allow`
- [ ] Test: `decision_carries_policy_effects`
- [ ] Verify: `cargo test --workspace` passes

### 0.9 — Module split (authorize.rs → 5 files)
- [ ] Create `crates/agentguard-core/src/authorize/` directory
- [ ] Move `Decision` + `Effect` + `From<CedarDecision>` into `crates/agentguard-core/src/authorize/effect.rs`
- [ ] Move `Engine` (currently `Authorizer`) into `crates/agentguard-core/src/authorize/engine.rs`
- [ ] Move `build_entities` into `crates/agentguard-core/src/authorize/entities.rs`
- [ ] Delete the old `crates/agentguard-core/src/authorize.rs`
- [ ] Create `crates/agentguard-core/src/authorize/mod.rs` re-exporting `effect::{Decision, Effect}`, `engine::Engine`, `entities::build_entities`
- [ ] Public type alias `pub type Authorizer = Engine;` in mod.rs for back-compat
- [ ] Verify: `cargo test --workspace` passes

### 0.10 — Module split (decision.rs → directory)
- [ ] Create `crates/agentguard-core/src/decision/` directory
- [ ] Move `DecisionRecord` into `decision/record.rs`
- [ ] Move `DecisionLog` into `decision/log.rs`
- [ ] Delete `crates/agentguard-core/src/decision.rs`
- [ ] Create `crates/agentguard-core/src/decision/mod.rs` re-exporting both
- [ ] Verify: `cargo test --workspace` passes

### 0.11 — Module split (policy.rs → directory)
- [ ] Create `crates/agentguard-core/src/policy/` directory
- [ ] Move `PolicyStore` into `policy/store.rs`
- [ ] Move `init_store` into `policy/init.rs`
- [ ] Move `PolicySource`, `ValidationReport`, `ValidationIssue`, `Severity` into `policy/types.rs`
- [ ] Delete `crates/agentguard-core/src/policy.rs`
- [ ] Create `crates/agentguard-core/src/policy/mod.rs`
- [ ] Verify: `cargo test --workspace` passes

### 0.12 — Decision cache placeholder
- [ ] Create `crates/agentguard-core/src/decision/cache.rs` with empty stub struct `pub struct DecisionCache;` and a `TODO(stage-5)` comment
- [ ] Add to `decision/mod.rs` re-exports: `pub use cache::DecisionCache;`
- [ ] Verify: `cargo test --workspace` passes (this stage doesn't implement the cache — just reserves the module path)

### 0.13 — Observability module skeleton
- [ ] Create `crates/agentguard-core/src/observability/` directory
- [ ] Create `crates/agentguard-core/src/observability/mod.rs` with:
  - `pub use span::*;` and `pub use request_id::*;`
- [ ] Create `crates/agentguard-core/src/observability/span.rs` with `TODO(stage-1)` marker — empty for now
- [ ] Create `crates/agentguard-core/src/observability/request_id.rs` with the `RequestId(Uuid)` newtype — moved from a free `String` field
- [ ] Update `AgentRequest.request_id: Option<RequestId>` (was `Option<String>`)
- [ ] Verify: `cargo test --workspace` passes

### 0.14 — Builder pattern for AgentRequest
- [ ] Create `AgentRequestBuilder` in `crates/agentguard-core/src/request.rs`:
  ```rust
  pub struct AgentRequestBuilder { ... }
  impl AgentRequestBuilder {
      pub fn new(principal: impl Into<Principal>) -> Self;
      pub fn action(self, a: impl Into<AgentAction>) -> Self;
      pub fn resource(self, r: impl Into<Resource>) -> Self;
      pub fn context(self, c: impl Into<AgentContext>) -> Self;
      pub fn traceparent(self, tp: TraceContext) -> Self;
      pub fn request_id(self, id: impl Into<RequestId>) -> Self;
      pub fn build(self) -> AgentRequest;
  }
  ```
- [ ] Keep `AgentRequest::new(...)` for back-compat; have it delegate to `AgentRequestBuilder::new(...).build()`
- [ ] Test: `builder_sets_all_fields`
- [ ] Verify: `cargo test --workspace` passes

### 0.15 — Error variant rename (RFC 8725 §3.1 hygiene)
- [ ] `Error::TokenSignatureInvalid` (unit) → `Error::TokenSignature { reason: String }`
- [ ] Update all `Error::TokenSignatureInvalid` call sites
- [ ] Add `#[non_exhaustive]` to `Error` enum (prevents downstream from exhaustive matching)
- [ ] Verify: `cargo test --workspace` passes

### 0.16 — CLI clap cleanup
- [ ] All `#[arg(long)]` field names match CLI flags exactly (already done in v1, verify)
- [ ] All `#[command(...)]` blocks have `long_about` for documentation
- [ ] Verify: `cargo build --workspace` and `cargo run --bin agentguard -- --help` look clean

### 0.17 — Documentation pass
- [ ] Every `pub` item in `agentguard_core` has a `///` doc comment
- [ ] `cargo doc --workspace --no-deps` produces no warnings
- [ ] Add `# Examples` section to `AgentRequestBuilder::build()` and `Authorizer::new()`

### 0.18 — Final verification
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` shows: 8 tests in `agentguard_core`, 0 in `agentguard_cli`, 0 in new stubs
- [ ] `cargo doc --workspace --no-deps` produces no warnings
- [ ] All examples in `examples/` still work end-to-end

## Commit

```bash
git add -A
git commit -m "stage(0): style, layout, architecture hardening

- Add rustfmt.toml and clippy.toml at repo root
- Restructure workspace with placeholder crates for stages 1-7
- Split request.rs into principal/action/resource/context/request modules
- Split authorize.rs, decision.rs, policy.rs into submodules
- Add typed IDs (PrincipalId, ActionId, ResourceId), Duration-based TTLs, Clock trait
- Add TraceContext (W3C) + RequestId (Uuid v7) auto-population
- Add AgentRequestBuilder with type-safe setters
- Surface per-policy effects in Decision
- Rename Error::TokenSignatureInvalid to Error::TokenSignature { reason }
- Mark Error as #[non_exhaustive]
- Remove all dead code (ActionDef, KeyBundle, Error::Cedar, _schema_anchor, unused fields)
- Update doc comments across the public API

No behavior change from v1. All 8 core tests still pass."
```

## Done when

- [ ] Commit landed on master
- [ ] `git log --oneline -3` shows the stage-0 commit as HEAD
- [ ] `cargo test --workspace` shows 8 passing tests in core
- [ ] No `TODO(stage-0)` comments remain in the workspace
- [ ] You can move to Stage 1

## What NOT to do in Stage 0

- Do not implement OTel, hash chains, JWT, DPoP, AuthZEN, sidecar, or any feature from later stages
- Do not change the policy or delegation token formats yet (hard break happens in Stage 4)
- Do not add new dependencies beyond `humantime`, `uuid` (already present), `parking_lot` (or `std::sync::Mutex` if you prefer no new deps)
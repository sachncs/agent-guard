# Stage 2 — Decision log v2 + HMAC hash chain

**Goal:** Tamper-evident audit log. Each record chained to the previous via HMAC-SHA256.

**Pre-flight:** Stage 1 complete. Telemetry crate compiles and tests pass.

## Todos

### 2.1 — Hash chain module
- [ ] `crates/agentguard-core/src/decision/chain.rs` with:
  ```rust
  pub struct HashChain {
      root: Arc<HMAC<Sha256>>,
      last_hash: parking_lot::Mutex<[u8; 32]>,
      chain_id: ChainId,
  }
  pub struct ChainId(pub Uuid);
  ```
- [ ] `HashChain::new(secret: &[u8]) -> Self` initializes with `last_hash = [0; 32]`
- [ ] `HashChain::from_file(path: &Path) -> Result<Self>` reads the chain head from a sidecar file `.chain` next to the log
- [ ] `pub fn append(&self, canonical_record: &[u8]) -> [u8; 32]` computes `HMAC(root, prev_hash || record)` and updates `last_hash`
- [ ] `pub fn verify_chain(records: impl Iterator<Item = Record>, root_key: &[u8]) -> Result<(), ChainError>` walks records and verifies each HMAC
- [ ] Use `hmac` + `sha2` + `hex` crates
- [ ] Test: `chain_appends_and_verifies_correctly`

### 2.2 — Canonical serialization
- [ ] `crates/agentguard-core/src/decision/canonical.rs`:
  - `pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error>`
  - Uses `serde_json::to_vec` with sorted keys (RFC 8785-style canonical JSON)
  - Test: `canonical_json_is_deterministic` — same struct in different orders produces same bytes

### 2.3 — DecisionRecord v2 schema
- [ ] Add fields to `DecisionRecord`:
  - `chain_id: Option<Uuid>`
  - `prev_hash: Option<String>` (hex-encoded)
  - `record_hash: Option<String>` (hex-encoded)
  - `tenant_id: Option<String>`
  - `subject_id: Option<String>` (alias for `principal`, for SAR queries)
  - `data_categories: Option<Vec<String>>` (e.g. `["email_address", "ip_address"]`)
  - `legal_basis: Option<String>` (e.g. `"consent"`, `"contract"`, `"legitimate_interest"`)
  - `retention_class: Option<String>` (e.g. `"30d"`, `"7y"`)
- [ ] Old readers ignore new fields (serde `#[serde(default)]`)
- [ ] Test: `record_v2_roundtrip`

### 2.4 — DecisionLog v2
- [ ] `crates/agentguard-core/src/decision/log.rs`:
  - `DecisionLog::open_with_chain(path, secret) -> Result<Self>`
  - `append(record)` automatically computes `prev_hash`, `record_hash`, fills in `chain_id`
  - `append_decision(d, trace_ctx)` — high-level helper
  - `verify() -> Result<(), ChainError>` — reads file, walks chain, asserts each HMAC
- [ ] Back-compat: `DecisionLog::open(path)` continues to work (no chain)
- [ ] Test: `log_writes_chained_records`, `log_detects_tampering`

### 2.5 — CLI commands
- [ ] `agentguard audit verify [--audit <path>] [--secret-file <path>]` — walks `.audit/decisions.jsonl` and verifies HMAC chain
- [ ] `agentguard audit notarize --secret-file <path>` — writes the current chain head to `.audit/chain.head` (also signs it with a public key for external notarization — Stage 3 optional)
- [ ] `agentguard audit export --format jsonl|cef|leef|ecs` — re-formats the log for SIEM ingestion
- [ ] Test: CLI integration test that writes 3 records, verifies, tampers with one byte, verifies again

### 2.6 — CEF/LEEF/ECS formatters
- [ ] `crates/agentguard-core/src/decision/formatter.rs`:
  - Trait `pub trait AuditFormatter { fn format(&self, rec: &DecisionRecord) -> String; }`
  - `JsonlFormatter` (default — pass-through)
  - `CefFormatter` — emits `CEF:0|agentguard|agentguard|2.0|<event_id>|authz_decision|<severity>|...`
  - `LeefFormatter` — emits LEEF 2.0 with `devTime`, `usrName`, `action`, `outcome`, etc.
  - `EcsFormatter` — emits ECS-compatible JSON with `@timestamp`, `event.action`, `event.outcome`, `user.id`, `labels.*`
- [ ] `DecisionLog::export(formatter, writer)` writes formatted output to a writer
- [ ] Test: `cef_format_matches_spec`, `ecs_format_has_required_fields`

### 2.7 — Subject access / erasure (compliance hooks)
- [ ] `crates/agentguard-core/src/decision/sar.rs`:
  - `pub fn subject_access(records: impl Iterator<Item = DecisionRecord>, subject_id: &str) -> Vec<DecisionRecord>` — filter
  - `pub fn pseudonymize(record: &mut DecisionRecord, salt: &[u8])` — replace `principal` with `HMAC(salt, principal)`
- [ ] CLI: `agentguard audit sar <subject_id> --audit <path>` prints matching records
- [ ] CLI: `agentguard audit erase <subject_id> --audit <path> --salt <hex>` writes a new file with pseudonymized records
- [ ] Test: `sar_filters_by_principal`, `pseudonymize_is_reversible_with_salt`

### 2.8 — Wire hash chain into Authorizer
- [ ] `Authorizer::new()` no longer creates a `DecisionLog` — that's a sink's job (Stage 1 already provides JSONL sink; v2 adds chain-aware JSONL sink)
- [ ] Add `AgentguardSink::chained_jsonl(path, secret)` factory in telemetry crate that wraps `DecisionLog::open_with_chain`
- [ ] Test: end-to-end — fire 3 authorizations with chained JSONL sink, verify chain, tamper, re-verify (should fail with line number)

### 2.9 — Final verification
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo doc --workspace --no-deps` no warnings
- [ ] `cargo run --bin agentguard -- audit verify --audit .audit/decisions.jsonl` works on a freshly-generated log
- [ ] `cargo run --bin agentguard -- audit export --format ecs --audit .audit/decisions.jsonl` produces ECS JSON

## Commit

```bash
git add -A
git commit -m "stage(2): HMAC-chained audit log + SIEM formatters

- New decision::chain module (HMAC-SHA256 hash chain, RFC 8785 canonical JSON)
- DecisionRecord v2 schema: chain_id, prev_hash, record_hash, tenant_id, subject_id, data_categories, legal_basis, retention_class
- DecisionLog::open_with_chain(path, secret) for tamper-evident writes
- agentguard audit verify / notarize / sar / erase / export commands
- CEF, LEEF, ECS audit formatters for SIEM ingestion
- Back-compat: DecisionLog::open(path) still works without a chain secret"
```

## Done when
- [ ] Commit landed
- [ ] All hash-chain tests pass
- [ ] `audit verify` detects a tampered record
- [ ] `audit export --format ecs` produces valid ECS JSON
- [ ] Move to Stage 3

## What NOT to do
- Do not implement JWT/OIDC/DPoP/SPIFFE yet (Stage 3)
- Do not implement decision cache yet (Stage 5)
- Do not implement AuthZEN server yet (Stage 7)
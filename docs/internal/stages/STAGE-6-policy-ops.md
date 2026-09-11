# Stage 6 — Policy operations crate (versions, hot reload, diff, blast radius)

**Goal:** Production-grade policy lifecycle. Versioned bundles, hot reload on file
change, blast-radius analysis before deploy.

**Pre-flight:** Stage 5 complete. Decision cache invalidates on policy change.

## Todos

### 6.1 — Crate setup
- [ ] `crates/agentguard-policy/Cargo.toml`:
  - Dependencies: `serde`, `serde_json`, `notify`, `tokio`, `async-trait`, `thiserror`, `sha2`, `hex`, `ed25519-dalek`
- [ ] `src/lib.rs`: re-export modules

### 6.2 — Versioned bundles
- [ ] `crates/agentguard-policy/src/version.rs`:
  ```rust
  pub struct PolicyVersion(u64);
  pub struct PolicyBundle {
      version: PolicyVersion,
      tenant_id: String,
      schema_hash: [u8; 32],
      policies_hash: [u8; 32],
      created_at: Timestamp,
      created_by: String,
      signature: Option<Ed25519Signature>,  // for tamper-evidence
      schema: String,
      policies: Vec<NamedPolicy>,
  }
  pub struct NamedPolicy { id: String, source: String }
  ```
- [ ] `PolicyBundle::from_store(root: &Path, version: PolicyVersion, tenant_id: &str) -> Result<Self, PolicyError>`
- [ ] `PolicyBundle::to_store(&self, root: &Path) -> Result<()>` — writes schema + policies
- [ ] `PolicyBundle::verify(&self) -> Result<(), PolicyError>` — checks signature if present
- [ ] `pub fn compute_hash(&self) -> [u8; 32]` — SHA-256 of canonical (schema || policies)
- [ ] Test: `bundle_roundtrip_preserves_content`, `bundle_signature_verifies`

### 6.3 — Bundle registry
- [ ] `crates/agentguard-policy/src/bundle.rs`:
  ```rust
  pub struct BundleRegistry {
      bundles: parking_lot::RwLock<BTreeMap<PolicyVersion, PolicyBundle>>,
      tenant_id: String,
  }
  ```
- [ ] `register(bundle)` — add
- [ ] `current() -> &PolicyBundle` — latest
- [ ] `at(version) -> Option<&PolicyBundle>`
- [ ] `rollback(target: PolicyVersion) -> PolicyVersion` — emits event
- [ ] Persists to `~/.agentguard/bundles/<tenant>/<version>.json` with optional signing
- [ ] Test: `registry_rollback_works`

### 6.4 — File watcher
- [ ] `crates/agentguard-policy/src/watch.rs`:
  ```rust
  pub struct PolicyWatcher {
      store_root: PathBuf,
      on_change: Box<dyn Fn(PathBuf) + Send + Sync>,
  }
  ```
- [ ] Uses `notify` crate's `RecommendedWatcher`
- [ ] Watches `.agentguard/schema.cedarschema` and `.agentguard/policies/`
- [ ] Debounces 100ms (multiple writes in flight)
- [ ] On change: validates policies, creates new `PolicyBundle`, increments version, invalidates cache (Stage 5 hook)
- [ ] Test: `watcher_detects_file_change` (uses `tempfile` + 200ms sleep)

### 6.5 — Diff
- [ ] `crates/agentguard-policy/src/diff.rs`:
  - `pub fn diff_bundles(old: &PolicyBundle, new: &PolicyBundle) -> BundleDiff`
  - `BundleDiff { added_policies: Vec<String>, removed_policies: Vec<String>, modified_policies: Vec<PolicyChange> }`
  - `PolicyChange { id: String, old_source: String, new_source: String, line_diff: Vec<DiffLine> }`
  - Use the `similar` crate for line diff
- [ ] CLI: `agentguard policy diff --old=<path> --new=<path>` outputs unified diff
- [ ] Test: `diff_detects_added_policy`, `diff_detects_modified_policy`

### 6.6 — Blast radius
- [ ] `crates/agentguard-policy/src/blast_radius.rs`:
  - `pub struct BlastRadiusReport { .. }`
  - `pub async fn analyze(old: &PolicyBundle, new: &PolicyBundle, replay_set: &[ReplayRequest]) -> Result<BlastRadiusReport, PolicyError>`
  - For each request in replay set, evaluates against old and new policies, classifies:
    - `AllowToDeny` (DANGEROUS — counts)
    - `DenyToAllow` (often a bug — counts)
    - `Unchanged`
  - `BlastRadiusReport { allow_to_deny: usize, deny_to_allow: usize, unchanged: usize, by_policy: HashMap<String, PolicyBlast> }`
  - `PolicyBlast { id, allow_to_deny_count, deny_to_allow_count, sample_changes: Vec<SampleChange> }`
- [ ] CLI: `agentguard policy blast-radius --old=v1 --new=v2 --replay=last_24h.jsonl`
- [ ] Test: `blast_radius_detects_allow_to_deny`

### 6.7 — Dry-run / shadow mode
- [ ] `Authorizer::with_shadow_bundle(bundle: PolicyBundle)` — runs a secondary evaluator in parallel
- [ ] Primary decision is enforced; shadow decision is attached to the record as `shadow_decision`
- [ ] Decision record gains `shadow_effect: Option<Effect>` and `shadow_policies: Option<Vec<String>>`
- [ ] Test: `shadow_decision_attached_to_record`

### 6.8 — Wire into Authorizer
- [ ] `Authorizer::new(store)` reads the latest bundle from `BundleRegistry`
- [ ] When `PolicyWatcher` fires, Authorizer atomically swaps to the new bundle
- [ ] `Authorizer::current_version() -> PolicyVersion`
- [ ] Test: `authorizer_picks_up_policy_reload`

### 6.9 — CLI commands
- [ ] `agentguard policy diff --old=v1 --new=v2` (by version or by file path)
- [ ] `agentguard policy rollback <version>`
- [ ] `agentguard policy list` — show all versions in registry
- [ ] `agentguard policy show <version>` — dump bundle contents
- [ ] `agentguard policy blast-radius --old=v1 --new=v2 --replay=file.jsonl`
- [ ] `agentguard policy watch` — long-running, prints reload events
- [ ] `agentguard policy dry-run --bundle=v2 --percent=10` — runs shadow evaluator
- [ ] Test: CLI smoke tests for each command

### 6.10 — Final verification
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo doc --workspace --no-deps` no warnings
- [ ] End-to-end: edit a `.cedar` file, watcher detects, cache invalidates, next `authorize` uses new policy

## Commit

```bash
git add -A
git commit -m "stage(6): policy operations — versions, hot reload, diff, blast radius

- New crates/agentguard-policy crate
- PolicyBundle with version, tenant, hash, optional Ed25519 signature
- BundleRegistry: versioned bundles, rollback, persistence
- PolicyWatcher: notify-based file watcher with 100ms debounce
- diff: unified text diff between two bundles (similar crate)
- blast_radius: replay-driven analysis counting allow→deny and deny→allow flips
- dry-run / shadow mode: secondary evaluator attached to decision record
- CLI: agentguard policy {diff, rollback, list, show, blast-radius, watch, dry-run}
- Authorizer reloads on watcher events, invalidates decision cache atomically"
```

## Done when
- [ ] Commit landed
- [ ] All policy-ops tests pass
- [ ] File watcher detects edits within 200ms
- [ ] Cache invalidates on policy change
- [ ] Move to Stage 7

## What NOT to do
- Do not implement the AuthZEN HTTP server yet (Stage 7)
- Do not break the `.agentguard/` directory layout
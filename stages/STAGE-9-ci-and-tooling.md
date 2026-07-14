# Stage 9 — CI, doctor, benchmarks

**Goal:** Production polish. CI catches regressions, `agentguard doctor` diagnoses
deployments, benchmark suite tracks performance.

**Pre-flight:** Stage 8 complete. All SDK features working.

## Todos

### 9.1 — GitHub Actions CI
- [ ] `.github/workflows/ci.yml`:
  - Triggers: push to master, pull request
  - Jobs:
    - `rust-fmt`: `cargo fmt --all -- --check`
    - `rust-clippy`: `cargo clippy --workspace --all-targets -- -D warnings`
    - `rust-test`: `cargo test --workspace`
    - `rust-doc`: `cargo doc --workspace --no-deps`
    - `rust-build`: `cargo build --workspace --release`
    - `python-test`: setup Python, install SDK, run `pytest`
    - `ts-build`: setup Node, install deps, `npm run build`
    - `examples-smoke`: run each `examples/*/main.py` end-to-end
- [ ] Use `actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, `actions/setup-python@v5`, `actions/setup-node@v4`
- [ ] Cache cargo + pip + npm
- [ ] Required status check: all jobs must pass

### 9.2 — rust-toolchain.toml
- [ ] Pin MSRV: `channel = "1.75"` (or whatever the workspace needs)
- [ ] `components = ["clippy", "rustfmt"]`

### 9.3 — agentguard doctor
- [ ] New CLI command `agentguard doctor` that diagnoses a deployment:
  - Schema loads OK
  - Policies parse OK
  - Schema validation passes
  - Bundle registry writable
  - Audit log writable
  - Audit log chain (if configured) verifies up to last record
  - Hash chain secret present (warning if not)
  - Auth config valid (if configured)
  - Telemetry exporting (warning if sinks configured but unreachable)
  - Decision cache size + hit rate (if enabled)
- [ ] Outputs human-readable table with ✓/✗/⚠ icons
- [ ] Exit code 0 if all OK, 1 if any ✗, 2 if any ⚠
- [ ] JSON mode (`--output json`) for programmatic checks
- [ ] Test: `doctor_reports_ok_on_healthy_store`

### 9.4 — Benchmarks
- [ ] `crates/agentguard-core/benches/authorize.rs`:
  - `benches/criterion_benches/authorize_bench.rs`
  - Benchmarks: simple request, complex request, large entity set, cached request, cold request
  - Use `criterion` crate
- [ ] `crates/agentguard-server/benches/authzen.rs`:
  - Benchmark AuthZEN endpoint throughput
- [ ] `cargo bench --workspace` runs all
- [ ] Document baseline performance in `docs/benchmarks.md`

### 9.5 — Doctests
- [ ] Add doc-tests to public APIs where helpful (don't add tests for trivial getters)
- [ ] `cargo test --workspace --doc` passes
- [ ] Example: `AgentRequestBuilder::build()` doc includes a runnable example

### 9.6 — CHANGELOG entry
- [ ] Update `CHANGELOG.md` with v2.0.0 entry (you wrote the skeleton in CHANGELOG.md earlier — fill in actual changes)
- [ ] Per the Keep a Changelog format:
  - Added: telemetry crate, auth crate, policy crate, server crate, hash-chained audit, decision cache, AuthZEN endpoints, etc.
  - Changed: delegation token format (v1 → JWS), error variants
  - Removed: v1 compact delegation token format

### 9.7 — README update
- [ ] Update `README.md` to reflect v2 features
- [ ] Add section: "What's new in v2.0.0" at the top
- [ ] Update installation: `pip install agentguard[full]` for all features
- [ ] Add quick-start for the server (`agentguard serve`)
- [ ] Link to all `examples/`
- [ ] Link to `docs/architecture.md` (already exists, may need updates)

### 9.8 — Architecture doc update
- [ ] Update `docs/architecture.md` to reflect v2 layout:
  - Mention telemetry, auth, policy, server crates
  - Show hash chain in audit log
  - Show W3C trace context propagation
  - Show AuthZEN endpoint shape
  - Document step-up auth flow

### 9.9 — Final verification
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo test --workspace --doc` passes
- [ ] `cargo bench --workspace --no-run` succeeds
- [ ] `pytest python/agentguard/tests -q` passes
- [ ] `cd typescript/agentguard && npm run build` passes
- [ ] `agentguard doctor` on a healthy store returns ✓
- [ ] CI passes locally (act, or manually run all checks)
- [ ] All examples in `examples/` work end-to-end

### 9.10 — Tag the release
- [ ] `git tag -a v2.0.0 -m "agentguard v2.0.0 — enterprise hardening"`
- [ ] `git push origin master --tags` (only when explicitly authorized by the user)
- [ ] Draft release notes referencing CHANGELOG.md

## Commit

```bash
git add -A
git commit -m "stage(9): CI, doctor, benchmarks, changelog

- .github/workflows/ci.yml: fmt, clippy, test, doc, build, python, ts, examples
- rust-toolchain.toml pinning MSRV 1.75
- agentguard doctor: deployment health check with ✓/✗/⚠ icons
- criterion benchmarks for authorize() and AuthZEN endpoint
- doctests on public APIs
- CHANGELOG.md: v2.0.0 entry with all changes
- README.md: v2 features, server quick-start, all examples linked
- docs/architecture.md: updated for v2 layout

Ready for v2.0.0 release."
```

## Done when
- [ ] Commit landed (v2.0.0-ready)
- [ ] All CI jobs pass locally
- [ ] All examples work end-to-end
- [ ] CHANGELOG and README are accurate
- [ ] `agentguard doctor` works
- [ ] Benchmarks produce baseline numbers

## What NOT to do
- Do not implement any new features (this stage is polish only)
- Do not change the public API
- Do not push the v2.0.0 tag without explicit user authorization
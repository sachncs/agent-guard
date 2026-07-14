# agentguard v2.0.0 — Implementation Stages

This directory tracks the implementation plan for v2.0.0 (enterprise hardening).
Each stage file is a contract: read it before touching code, check off each todo
as you complete it, and verify the verification commands pass before moving on.

## Stage order (do not skip)

1. [Stage 0 — Style, layout, and architecture hardening](STAGE-0-style-and-architecture.md)
2. [Stage 1 — Telemetry crate](STAGE-1-telemetry.md)
3. [Stage 2 — Decision log v2 + hash chain](STAGE-2-decision-log-hash-chain.md)
4. [Stage 3 — Auth crate (JWT, OIDC, API keys, DPoP, SPIFFE)](STAGE-3-auth.md)
5. [Stage 4 — Delegation v2 (JWS, RFC 8693, structured constraints)](STAGE-4-delegation-v2.md)
6. [Stage 5 — TTL & decision cache](STAGE-5-ttl-and-cache.md)
7. [Stage 6 — Policy operations crate (versions, hot reload, diff)](STAGE-6-policy-ops.md)
8. [Stage 7 — Server crate (AuthZEN HTTP + gRPC sidecar)](STAGE-7-server.md)
9. [Stage 8 — SDK updates (in-process, step-up, traceparent)](STAGE-8-sdk-updates.md)
10. [Stage 9 — CI, doctor, benchmarks](STAGE-9-ci-and-tooling.md)

## Verifying completion of all stages

```bash
# At repo root, after all stages complete:
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release

# Python SDK
pip install -e python/agentguard python/agentguard_langchain
pip install -e python/agentguard-server-sdk    # after stage 7
pytest python/agentguard/tests -q

# TypeScript SDK
cd typescript/agentguard && npm run build && npm test

# All examples run end-to-end
for ex in examples/*/; do [ -f "$ex/main.py" ] && (cd "$ex" && python main.py); done
```

A stage is complete when:
- All todos in its file are checked off
- `cargo test --workspace` passes
- `cargo clippy --workspace --all-targets -- -D warnings` passes
- New examples (if any) run successfully
- The git commit for that stage is made

## Cross-stage invariants

These must remain true at the end of every stage:

1. `cargo build --workspace` succeeds with no warnings.
2. Every public function in `agentguard_core` has a doc comment.
3. Every error variant is `#[non_exhaustive]` where it could gain variants.
4. Every `pub` struct derives `Debug, Clone, Serialize, Deserialize` (where serde applies).
5. Every new feature has at least one test.
6. Atomic commits: one commit per stage, message format `stage(N): <verb> <what>`.
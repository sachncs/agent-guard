# Stage 8 — SDK updates (in-process, step-up, traceparent)

**Goal:** Python and TypeScript SDKs use cedar-policy bindings for in-process
mode. Step-up auth surfaces correctly. Trace context propagates through.

**Pre-flight:** Stage 7 complete. Server runs and SDK round-trips work.

## Todos

### 8.1 — Python: in-process mode
- [ ] Add `cedar-policy` Python bindings as a dependency (`pip install cedar-policy`)
- [ ] `python/agentguard/src/agentguard/client.py`:
  - `Client(..., mode: Literal["subprocess", "in_process"] = "subprocess")`
  - In-process mode: imports `cedar_policy` and builds requests directly
  - Same `Decision` dataclass, same `authorize(...)` API
- [ ] Performance test: in-process mode should be 10-100x faster than subprocess
- [ ] Test: `in_process_mode_returns_same_decision_as_subprocess`

### 8.2 — Python: traceparent passthrough
- [ ] `Client.authorize(..., traceparent: str | None = None)`:
  - If provided, parses W3C `traceparent`, embeds in the request
  - Server/CLI emits span with matching `trace_id`
- [ ] `Client.delegate(..., traceparent: str | None = None)` — same
- [ ] Test: `traceparent_round_trips_through_authorize`

### 8.3 — Python: bearer token / JWT
- [ ] `Client(..., auth_token: str | None = None, auth_token_type: Literal["Bearer", "DPoP"] = "Bearer")`
- [ ] All CLI invocations pass `Authorization: Bearer <token>` or `DPoP <token>`
- [ ] When `auth_token` is set, SDK auto-includes it
- [ ] Test: `bearer_token_sent_in_authorization_header`

### 8.3a — Python: DPoP
- [ ] `Client(..., dpop_key: DpopKey | None = None)` where `DpopKey` is a helper to manage the keypair
- [ ] SDK generates a DPoP proof JWT for each request, attaches `DPoP` header
- [ ] Test: `dpop_proof_attached_to_request`

### 8.4 — Python: StepUpRequired exception
- [ ] `errors.py`: `StepUpRequired(StepUp)` exception
- [ ] `client.authorize(..., on_step_up: Literal["raise", "return"] = "raise")` — return for non-LangChain use cases
- [ ] Test: `step_up_required_raised_on_mfa_missing`

### 8.5 — LangChain middleware updates
- [ ] `GuardConfig` gains `auth_token: str | None`, `dpop_key: ...`, `mode: ...`
- [ ] `GuardedTool._check()` propagates trace context from the runtime
- [ ] When decision requires step-up, raise `StepUpRequired` (not `PermissionError`)
- [ ] Add `on_step_up: Callable[[StepUp], Awaitable[None]] | None` to `GuardConfig` for custom handling
- [ ] Test: `step_up_surfaces_to_langchain`

### 8.6 — TypeScript: in-process mode
- [ ] Use `@cedar-policy/cedar-policy` npm package
- [ ] `Client({ ..., mode: "in_process" | "subprocess" })`
- [ ] Same API, same JSON contract
- [ ] Test: equivalent behavior across modes

### 8.7 — TypeScript: traceparent + bearer + DPoP
- [ ] Mirror Python changes
- [ ] Use `crypto.subtle` for DPoP signing

### 8.8 — TypeScript: Vercel AI SDK middleware (was deferred in v1)
- [ ] `typescript/packages/vercel-ai/` package
- [ ] `withAgentGuard({ client, ... })` wrapper for Vercel AI SDK
- [ ] Intercepts `generateText` / `streamText` calls, checks tool calls before execution
- [ ] Test: smoke test with a mock Vercel AI SDK call

### 8.9 — DecisionTrace Python dataclass
- [ ] `models.py`: `DecisionTrace` mirroring Rust's trace context (trace_id, span_id, etc.)
- [ ] `Decision.trace: DecisionTrace | None` field
- [ ] Test: `decision_carries_trace_context`

### 8.10 — Documentation
- [ ] Update `python/agentguard/README.md` with all new options
- [ ] Add an example: `examples/jwt-auth/main.py` (uses bearer token)
- [ ] Add an example: `examples/dpop-protected/main.py` (DPoP flow)
- [ ] Update `typescript/agentguard/README.md`

### 8.11 — Final verification
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] `pytest python/agentguard/tests -q` passes
- [ ] `cd typescript/agentguard && npm run build && npm test` passes
- [ ] In-process mode benchmark: ≥10x faster than subprocess
- [ ] Step-up flow works end-to-end

## Commit

```bash
git add -A
git commit -m "stage(8): SDK updates — in-process mode, step-up, traceparent

- Python SDK: mode=in_process|subprocess, uses cedar-policy PyO3 bindings
- Python SDK: traceparent, bearer_token, DPoP key passthrough
- Python SDK: StepUpRequired exception, on_step_up parameter
- TypeScript SDK: same features mirrored using @cedar-policy/cedar-policy
- Vercel AI SDK middleware (new typescript/packages/vercel-ai)
- Decision.trace: TraceContext (trace_id, span_id, parent_span_id)
- New examples: jwt-auth, dpop-protected
- LangChain middleware surfaces StepUpRequired with custom callback"
```

## Done when
- [ ] Commit landed
- [ ] In-process mode is measurably faster than subprocess
- [ ] Step-up auth works through LangChain
- [ ] Vercel AI SDK middleware works
- [ ] Move to Stage 9

## What NOT to do
- Do not add CI workflows yet (Stage 9)
- Do not add `doctor` or benchmarks yet (Stage 9)
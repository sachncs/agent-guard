# Stage 4 — Delegation v2 (JWS, RFC 8693 act chain, structured constraints)

**Goal:** Replace v1's custom compact token format with standard JWS. Add
RFC 8693 token-exchange semantics with nested `act` claim chains. Add structured
constraints that are verified at evaluation time.

**Pre-flight:** Stage 3 complete. Auth crate compiles and tests pass.

**Breaking change:** v1 delegation token format (`payload.sig.kid`) is dropped.

## Todos

### 4.1 — Drop v1 format
- [ ] Delete `DelegationToken.to_compact()` and `DelegationToken::from_compact()`
- [ ] Replace with JWS serialization:
  ```rust
  impl DelegationToken {
      pub fn to_jws(&self) -> Result<String, DelegationError>;   // header.payload.sig
      pub fn from_jws(s: &str) -> Result<Self, DelegationError>;
  }
  ```
- [ ] JWS header: `{ "alg": "EdDSA", "kid": "<key_id>", "typ": "agentguard-delegation+jwt" }`
- [ ] Update CLI `agentguard delegate` and `agentguard verify` to use JWS only
- [ ] Update Python SDK to emit/consume JWS only

### 4.2 — Structured constraints
- [ ] `DelegationClaims` gains `constraints: Option<Constraints>`
- [ ] `Constraints` is a structured JSON tree, not a free-form string:
  ```rust
  pub struct Constraints { /* a tree of expressions */ }
  pub enum ConstraintExpr {
      Equals(serde_json::Value),
      In(Vec<serde_json::Value>),
      GreaterThan(i64),
      LessThan(i64),
      Glob(String),
      And(Vec<ConstraintExpr>),
      Or(Vec<ConstraintExpr>),
      Not(Box<ConstraintExpr>),
  }
  ```
- [ ] Constraint path syntax: `context.args.amount`, `context.session.ip`, `principal.tenant_id`
- [ ] `Verifier::verify_with_constraints(claims, request_context) -> Result<(), AuthError>`:
  - Walks each constraint, evaluates against the request context
  - Returns `ConstraintViolation { path, expr }` on mismatch
- [ ] Backward: `resource_patterns` field kept (as glob constraint) for compatibility within v2

### 4.3 — RFC 8693 act claim chain
- [ ] `DelegationClaims` gains `act: Option<ActClaim>` for nested chains
- [ ] `ActClaim { sub: String, iss: String, act: Option<Box<ActClaim>> }` (recursive)
- [ ] `DelegationClaims::chain() -> Vec<String>` returns the chain `User → Agent → SubAgent → ...`
- [ ] Verifier checks the entire chain: signature at each level must be valid; expirations must form a monotonic non-increasing sequence (outer tokens can't outlive their parents)
- [ ] Test: `nested_act_chain_verifies`, `nested_act_chain_rejects_outer_exceeds_inner`

### 4.4 — Step-up auth integration
- [ ] When `Constraints` includes `context.session.amr contains "mfa"`, the request must have MFA in its session context
- [ ] Otherwise verifier returns `StepUpRequired { acr_values: "urn:mace:incommon:iap:silver", amr_values: "mfa hwk" }` (this is the new `AuthError` variant)
- [ ] Test: `step_up_required_when_mfa_missing`

### 4.5 — Algorithm agility
- [ ] `DelegationSigner` gains `with_algorithm(Algorithm)` constructor — supports EdDSA, ES256, RS256
- [ ] `Algorithm` enum lives in `crates/agentguard-auth/src/lib.rs` (shared with JWT validator)
- [ ] `DelegationVerifier` resolves algorithm from JWS header (verified against whitelist)
- [ ] Test: `signer_with_es256_verifies_via_es256`, `signer_rejects_alg_confusion`

### 4.6 — Audience restriction
- [ ] `DelegationClaims.aud` is required (already is)
- [ ] Verifier checks `claims.aud` matches the configured audience per agent
- [ ] CLI `agentguard delegate` requires `--audience <uri>` (RFC 8707 resource indicator format)
- [ ] Test: `audience_mismatch_rejected`

### 4.7 — Wire into Authorizer
- [ ] `authorize()` accepts `delegation_token: Option<&DelegationToken>`
- [ ] If provided, verifier runs FIRST; if invalid → Deny with reason
- [ ] Constraints are cross-checked against request context; mismatch → Deny with `ConstraintViolation` reason
- [ ] Decision record gains `delegation_token_id: Option<String>` (the token's `jti`)
- [ ] Test: `authorize_with_valid_delegation`, `authorize_with_expired_delegation`

### 4.8 — CLI updates
- [ ] `agentguard delegate --audience <uri>` (required)
- [ ] `agentguard delegate --constraint "context.args.amount < 10000"` (parse humantime-like expressions)
- [ ] `agentguard delegate --act <parent_jws>` (chain to a parent token)
- [ ] `agentguard verify` outputs the `act` chain in human-readable form
- [ ] Test: CLI smoke test — mint a chained delegation, verify it

### 4.9 — Python SDK updates
- [ ] `Client.delegate(...)` signature gains `audience`, `constraints`, `parent_token`
- [ ] `Client.verify(token)` returns claims including `act` chain
- [ ] Old `compact_token` format is no longer accepted
- [ ] Update TypeScript SDK to match

### 4.10 — Final verification
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo doc --workspace --no-deps` no warnings
- [ ] `agentguard delegate --audience "agentguard://prod/email" --constraint "context.args.amount < 1000" --act <parent>` works end-to-end
- [ ] `agentguard verify` on a chained token prints the User → Agent → SubAgent hierarchy

## Commit

```bash
git add -A
git commit -m "stage(4): delegation v2 — JWS, RFC 8693 act, structured constraints

- BREAKING: drop v1 compact token format; JWS only
- Structured constraints (Equals, In, GreaterThan, Glob, And/Or/Not) with path-based access
- RFC 8693 act claim chain (User → Agent → SubAgent → ...)
- Algorithm agility: EdDSA, ES256, RS256 with explicit whitelist (RFC 8725 §3.1)
- Audience restriction enforcement (RFC 8707)
- Step-up auth integration via Constraints
- DelegationToken::to_jws / from_jws replaces v1 to_compact / from_compact
- CLI: agentguard delegate requires --audience, supports --constraint, --act
- Authorizer::authorize accepts delegation_token parameter"
```

## Done when
- [ ] Commit landed
- [ ] All delegation v2 tests pass
- [ ] Old v1 tokens are rejected with a clear error
- [ ] Chained delegation works end-to-end
- [ ] Move to Stage 5

## What NOT to do
- Do not implement decision cache yet (Stage 5)
- Do not implement AuthZEN server yet (Stage 7)
- Do not break the policy file format
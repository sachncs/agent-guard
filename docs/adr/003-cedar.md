# ADR-003: Cedar as the policy language

**Status**: Accepted (v2.0)

## Context

We need a policy language that's expressive enough for AI-agent
authorization but simple enough for non-security engineers to read.
Common candidates: OPA Rego, AWS IAM, custom DSL.

## Decision

We use [Cedar](https://www.cedarpolicy.com/) — the same policy
language AWS Verified Access uses.

Cedar is:

- **Deny-by-default**: missing policy ⇒ Deny. (IAM / OPA / Rego all
  need explicit `default deny`.)
- **Formally verified**: AWS-funded formal verification of the
  authorization engine (POPL 2024 paper).
- **Schema-validated**: policies are checked against a typed schema at
  load time. Typos in policy text fail closed.
- **Ecosystem**: native Rust binding (`cedar-policy` crate).

## Consequences

+ Audit-friendly: every policy decision can be re-derived from the
  Cedar logs offline.
+ Cedar's `Entity` types compose with our `Principal` / `Resource`
  / `AgentAction` types one-for-one.
- Cedar is single-vendor (AWS). The Rust binding is Apache-2.0 and
  self-contained, but new policy language features take time to
  reach the binding.
- Cedar doesn't natively model sub-agent delegation chains. We
  built that on top with `DelegationSigner` / `DelegationVerifier`
  and the structured `ConstraintExpr` language.

## Alternatives considered

- **OPA / Rego**: more expressive but doesn't have formal
  verification. Rego Datalog is harder for non-engineers to read.
- **AWS IAM JSON**: designed for cloud IAM, not sub-agent
  delegation chains.
- **Custom DSL**: full maintenance burden + no ecosystem.

## Operational impact

Schema is at `.agentguard/schema.cedarschema`. Policies at
`.agentguard/policies/*.cedar`. Validate with `agentguard validate`.
Author-time feedback is the primary mechanism; runtime failures are
last-resort and surface as 500.

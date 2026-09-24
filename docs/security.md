# Security model and operating boundaries

AgentGuard is an authorization component, not an agent sandbox or a general
prompt-injection detector. Its security value comes from placing a policy
decision immediately before a protected operation and making the caller stop
unless that decision explicitly permits execution.

This guide describes the security contract of the shipped components. It does
not replace a deployment-specific threat model, review of your Cedar policies,
or testing of every adapter and execution path.

## Authorization contract

Cedar evaluates the supplied principal, action, resource, context, and entity
set against the loaded policy bundle. No matching permit means deny; an
applicable forbid overrides a permit. Authorization is effective only when the
adapter:

1. derives principal and security-sensitive context from trusted systems;
2. submits the actual target and arguments immediately before execution;
3. executes only after an explicit allow and successful decision response; and
4. applies the same rule to retries, delegated calls, and alternate tool paths.

Timeouts, malformed responses, PDP failures, and configured audit failures
must not become implicit permission. The Strands guard demonstrates fail-closed
HTTP handling. Custom integrations must preserve that behavior. The CLI emits
its decision only after required audit persistence succeeds; on an audit error
it exits unsuccessfully without writing a decision to stdout. The explicit
`--skip-audit` option disables that guarantee and should only be used when the
caller has another durable audit path. The embedded `Authorizer` does not write
audit records automatically.

## Trust boundaries and identity

- Treat model output, tool arguments, browser input, and caller-supplied
  identity claims as untrusted.
- Derive identity, MFA, environment, group membership, ownership, and tenant
  facts from trusted systems. Do not let a model or untrusted caller provision
  its own API key or assert its own authorization facts.
- Standalone PDP API keys require an explicit scope and are bound to one `User`
  or `Agent` subject. Requests naming another subject are rejected. Optional
  tenant metadata is useful for audit and request tracking but is not itself a
  Cedar policy attribute; encode tenant isolation through trusted entity data
  and policy inputs.
- Keep PDP and console endpoints on trusted, encrypted network paths. The
  reference Kubernetes topology terminates external TLS at an ingress or
  service mesh. Its console-to-PDP hop uses plain HTTP inside the cluster
  unless a mesh enforces mTLS; NetworkPolicy limits reachability but does not
  encrypt traffic. See the [Kubernetes operations guide](kubernetes.md).
- In production, use OIDC over HTTPS for the console, shared Redis-compatible
  session and rate-limit stores, and secrets mounted through the deployment
  platform. Do not use development memory stores or commit secrets to policy
  configuration.

## Policy and lifecycle

Generated initialization policies are broad development grants. Replace and
review them before deployment; validate policy and schema changes before
activation. The standalone file watcher and SIGHUP path build a replacement
snapshot before swapping it in. Invalid edits retain the last-known-good
snapshot, but a successful reload does not prove that the new policy is safe.
Embedded `Authorizer` instances are immutable; the embedding application owns
rebuild and swap behavior.

The standalone PDP enables decision caching by default. Cache keys include the
canonical request, supplied Cedar entities, and policy version so changes to
identity, context, entity hierarchy, or policy do not reuse another decision.
Embedded applications opt into caching themselves and own lifecycle/config
integration.

## Audit evidence

The standalone server appends configured audit records durably and returns an
error when an append fails; readiness is withdrawn when configured audit
storage becomes unavailable. Chained logs use an HMAC secret and durable chain
identity metadata. Protect the secret and audit volume, retain independently
trusted chain-head checkpoints, and test restore procedures. A chain alone
does not prove completeness: a secret holder can forge records, and
verification without a trusted checkpoint cannot prove that earlier records
were not removed. The embedded authorizer does not create audit records unless
the embedding application supplies that lifecycle.

## Explicit exclusions and limitations

- AgentGuard does not detect every prompt injection, validate model reasoning,
  patch tool vulnerabilities, or protect an execution path that bypasses the
  authorization boundary.
- An allow means only that the supplied request matched policy. It is not proof
  that the operation is safe, correct, or successfully executed.
- The simulator uses a privileged `authorize:any` service key to evaluate
  selected subjects. Protect it server-side and restrict console users through
  OIDC and role configuration.
- Delegation scope checking is available on verified claims through
  `VerifiedDelegation::allows`; the application must supply the trusted acting
  identity and request facts. `DelegationSigner::mint_attenuated` constrains
  child grants to verified parent scopes and lifetime. Neither helper
  authorizes the original parent grant or evaluates Cedar policy. The async
  `DelegationRevocationStore` port and `agentguard-redis-store` adapter enable
  shared revocation checks, but an application must configure durable storage
  and use the store-aware verifier before each authorization. The verifier
  also requires the AgentGuard delegation JWS type, non-empty identity claims,
  and consistent time claims.
- JWT, DPoP, and SPIFFE are library capabilities, not standalone server auth
  modes. Standalone API-key authentication is the supported PDP mode.
- The standalone gRPC listener is plaintext and restricted to loopback; do not
  expose it outside that trust boundary.
- The Kubernetes reference deployment supports one PDP replica with
  operator-managed persistent audit storage. Multi-replica PDP operation is
  outside the shipped contract until a coordinated append-only audit backend
  is deployed.
- Stable API/LTS guarantees are outside the current compatibility promise;
  consult the [compatibility policy](compatibility.md) before upgrades.

## Production use

The supported reference deployment is Docker on Kubernetes, with persistent
policy/audit storage and the operator responsibilities documented in the
[production deployment guide](production.md). Review the complete
[Kubernetes](kubernetes.md), [console](console.md), [backup](backups.md), and
[incident response](incident-response.md) procedures before rollout. Test the
exact adapter, identity source, policy lifecycle, failure modes, and recovery
path that your application will use. A successful build or health probe does
not substitute for those checks.

For vulnerability reports, follow [`SECURITY.md`](../SECURITY.md) and use
GitHub's private vulnerability reporting. Do not publish exploit details in a
public issue.

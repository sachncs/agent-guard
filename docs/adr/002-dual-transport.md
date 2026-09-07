# ADR-002: AuthZEN HTTP + gRPC dual surface

**Status**: Accepted (v2.0)

## Context

The OpenID AuthZEN working group standardizes an HTTP
`POST /access/v1/evaluation` shape for PDPs. Some callers (especially
in-process sidecars) prefer gRPC. We need to support both with a
single policy engine.

## Decision

The `agentguard-server` crate exposes both:

- HTTP: `POST /access/v1/evaluation` and `POST /access/v1/evaluations`
  per the OpenID AuthZEN WG draft.
- gRPC: `agentguard.v1.AccessEvaluation` with the same wire shape
  (`subject` / `action` / `resource` / `context` / `entities`).

Both share a single `AppState` (the cedar engine + audit log +
metrics + auth layer). The gRPC handler delegates to the same
`evaluation_request_to_agent` helper as the HTTP handler, so the
wire semantics are byte-identical across transports.

## Consequences

+ One policy engine, one audit log, one auth layer for both
  transports.
+ Operators choose the transport that fits their deployment (HTTP
  in front of K8s ingress; gRPC in front of an in-cluster sidecar).
- Two proto implementations to maintain. Mitigated by the shared
  helper; the gRPC handler is ~100 LOC and the proto schema is
  ~50 lines.
- The HTTP and gRPC handlers must be tested separately. Done in
  `crates/agentguard-server/tests/{authzen,grpc_smoke}.rs`.

## Alternatives considered

- **HTTP only**: simpler, but loses the gRPC sidecar case.
- **gRPC only**: bad interop — most language SDKs would need a gRPC
  stub, and the AuthZEN standard is HTTP-first.
- **Two separate servers**: doubles the maintenance burden. The
  shared `AppState` design was the right call.

## Operational impact

`AGENTGUARD_GRPC_LISTEN` env var / `--grpc-listen` CLI flag opts in.
Empty disables gRPC. Operators who want HTTP only simply don't set
the flag — the gRPC server is not started.

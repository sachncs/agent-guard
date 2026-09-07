# ADR-001: Plain JSONL audit log + HMAC chain

**Status**: Accepted (v2.0)

## Context

We need a tamper-evident audit log for every authorization decision.
The log must be append-only and verifiable offline (without server
cooperation).

## Decision

Every authorization decision is written to a JSONL file. When
configured with a chain secret, each record carries:

- `prev_hash`: SHA-256(HMAC(root_key, prev_record_canonical_json))
- `record_hash`: SHA-256(HMAC(root_key, current_record_canonical_json))
- `chain_id`: UUID v4 (regenerated on file rotation)

The chain root is stored in a sidecar file (`.chainid`) so restarts
continue the same chain identity.

## Consequences

+ Records can be verified offline with `agentguard audit verify`.
+ A single secret is the chain root — easy to rotate (by file
  rotation, see operations/runbook.md).
+ Plain JSONL is also forward-compatible with log shippers (Vector,
  Fluent Bit, etc.).
- A single secret means the verifier and the signer must share the
  secret — there's no per-tenant key separation. For multi-tenant
  compliance use a tiered approach: hash the tenant_id into the
  chain head so cross-tenant tamper is detected.
- A corrupted tail is detected but not auto-recovered. Operators
  must archive the corrupt file and start a new chain.

## Alternatives considered

- **Per-record signing with a public key (RSA / EdDSA)**: same
  threat model, but the verifier needs to ship a public key.
  HMAC-with-shared-secret is simpler and meets our threat model
  (the operator already has access to the chain secret for verify).
- **Append-only blockchain / Merkle tree**: overkill for the
  decision volume.
- **No chain (plain JSONL)**: easy but unverifiable — rejected.

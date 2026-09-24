# Backups and retention

The operator owns durable policy and audit storage. AgentGuard's hash chain
detects tampering; it does not replace backups, replication, retention policy,
or disaster-recovery testing.

## What to preserve

- Policy files and Cedar schema, including the active version.
- The active audit JSONL file, every timestamped rotation segment, and each
  matching hidden `.chainid` sidecar. Preserve the original filenames and
  directory layout as one consistent set.
- The chain secret, delegation signing key, and their rotation metadata in a
  secret manager (never in Git or an image layer).
- The deployment manifests, image digests, and configuration export.
- Console session/rate-limit Redis data according to the organization's
  recovery point objective.
- Delegation revocation Redis state for at least the maximum accepted token
  lifetime plus verifier clock skew. Treat it as security state: configure
  `maxmemory-policy noeviction`, durable persistence, and backups/replication
  appropriate to the required recovery point objective.

## Backup procedure

Quiesce or coordinate writes, snapshot the complete audit directory (including
hidden sidecars), and verify the copied chain before declaring the backup
successful:

```sh
agentguard audit verify \
  --audit /backup/agentguard/.audit/decisions.jsonl \
  --secret-file /backup/agentguard/.chain-secret
```

For Kubernetes, snapshot the audit PVC using the storage provider's supported
mechanism. Store backups encrypted, restrict access to the security/platform
team, and test a restore into an isolated namespace at least once per release
cycle.

Do not resume delegated tool execution from a stale revocation snapshot without
accounting for revocations newer than that snapshot. If revocation state may
have been lost, keep delegated execution disabled until the store is recovered
or rotate affected delegation signing keys and remove the old verification
keys to invalidate outstanding grants. Restoring an older snapshot can
resurrect a revoked grant until its expiry; document this risk and the recovery
decision in the incident record.

The reference manifest rotates the active file at 64 MiB, but retains every
segment on the PVC. Configure external archival and PVC-capacity alerts for
the expected decision volume; rotation alone does not bound disk use. Archive
all segments and sidecars as one consistent set, verify the archived chain,
and only then apply the organization's separately approved retention policy.

## Retention and erasure

Set retention according to the organization's legal and incident-response
requirements. `audit erase` is a destructive privacy operation: it changes the
records and invalidates the original chain. Export and obtain approval before
erasure, record the operator and reason, then verify the resulting chain and
backup both the pre- and post-operation evidence according to policy.

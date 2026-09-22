# Backups and retention

The operator owns durable policy and audit storage. AgentGuard's hash chain
detects tampering; it does not replace backups, replication, retention policy,
or disaster-recovery testing.

## What to preserve

- Policy files and Cedar schema, including the active version.
- The audit JSONL file and its chain sidecar.
- The chain secret, delegation signing key, and their rotation metadata in a
  secret manager (never in Git or an image layer).
- The deployment manifests, image digests, and configuration export.
- Console session/rate-limit Redis data according to the organization's
  recovery point objective.

## Backup procedure

Quiesce or coordinate writes, copy the audit file and sidecar as one consistent
set, and verify the copied chain before declaring the backup successful:

```sh
agentguard audit verify --store /backup/agentguard
agentguard audit export --store /backup/agentguard --format jsonl > audit.jsonl
```

For Kubernetes, snapshot the audit PVC using the storage provider's supported
mechanism. Store backups encrypted, restrict access to the security/platform
team, and test a restore into an isolated namespace at least once per release
cycle.

## Retention and erasure

Set retention according to the organization's legal and incident-response
requirements. `audit erase` is a destructive privacy operation: it changes the
records and invalidates the original chain. Export and obtain approval before
erasure, record the operator and reason, then verify the resulting chain and
backup both the pre- and post-operation evidence according to policy.

# agentguard Operations Runbook

This runbook covers routine operations and common failure modes for
`agentguard` deployments.

## Quick health check

```bash
agentguard doctor
```

Returns exit code 0 if all checks pass; 1 on `✗` (failure); 2 on `⚠`
(warning). `--output json` for machine-readable output.

## Configuration

All settings have sensible defaults; overrides come from CLI flags
or environment variables. The full table:

| Env var | CLI flag | Default | Description |
|---------|----------|---------|-------------|
| `AGENTGUARD_LISTEN` | `--listen` | `tcp://127.0.0.1:8443` | Server listen address |
| `AGENTGUARD_STORE` | `--store` | `.agentguard` | Policy directory |
| `AGENTGUARD_AUDIT` | `--audit` | `.audit/decisions.jsonl` | Audit log path |
| `AGENTGUARD_CHAIN_SECRET` / `--secret-file` | — | (unset → plain JSONL) | HMAC chain secret (hex / base64 / raw) |
| `AGENTGUARD_AUTH` | `--auth` | `disabled` | `disabled` or `apikey:<path>` (point at the JSON key store) |
| `AGENTGUARD_GRPC_LISTEN` | `--grpc-listen` | (empty → disabled) | gRPC listen address |
| `AGENTGUARD_ALLOW_LOOPBACK_BYPASS` | — | `0` | Allow auth-disabled on public listener |
| `AGENTGUARD_CACHE_TTL` | — | `60s` | Decision cache allow TTL (humantime) |
| `AGENTGUARD_DENY_CACHE_TTL` | — | `5s` | Decision cache deny TTL (humantime) |
| `AGENTGUARD_CACHE_CAPACITY` | — | `10000` | Decision cache size |
| `AGENTGUARD_AUDIT_MAX_BYTES` | — | (unset → no rotation) | Rotate the audit log when the active file exceeds this size |
| `AGENTGUARD_JWKS_REFRESH` | — | `30s` | JWKS refresh interval (humantime) |

## Deployment

### Single-binary deploy

1. Generate an HMAC chain secret:
   ```bash
   head -c 32 /dev/urandom | base64 > .chain-secret
   chmod 0600 .chain-secret
   ```
2. Configure via environment (or CLI flags):
   ```bash
   export AGENTGUARD_LISTEN="tcp://0.0.0.0:8443"
   export AGENTGUARD_STORE="/etc/agentguard/policies"
   export AGENTGUARD_AUDIT="/var/log/agentguard/decisions.jsonl"
   export AGENTGUARD_CHAIN_SECRET="/etc/agentguard/.chain-secret"
   export AGENTGUARD_AUTH="apikey:/etc/agentguard/keys.json"
   export AGENTGUARD_GRPC_LISTEN="0.0.0.0:9443"
   ```
3. Generate API keys for callers. There is no `agentguard keygen`
   subcommand today; the key store is a JSON file holding a
   top-level array of `ApiKey` records (the shape produced by
   `agentguard_auth::ApiKeyStore`). Each entry is the result of
   calling `ApiKeyStore::create(prefix, scopes, ttl)`:

   ```rust
   // In a one-off `cargo run --example` against the workspace:
   let store = agentguard_auth::ApiKeyStore::new();
   let (_key, raw) = store.create("ag_live", vec![], None)?;
   store.save_to_file("/etc/agentguard/keys.json")?;
   // Surface `raw` (format: `<prefix>:<id>:<base64url>`) to the
   // caller exactly once. Only the Argon2id hash of the secret is
   // persisted in the JSON file.
   ```

   Manually-constructed files must satisfy the same `Vec<ApiKey>`
   shape: every `secret_hash` is a PHC-formatted Argon2id hash,
   not raw SHA-256.
4. Start the server. The watcher auto-reloads the policy directory on
   file change.

### Kubernetes

Standard Deployment + ConfigMap for policy + Secret for chain key +
PersistentVolumeClaim for `.audit/`. Set
`AGENTGUARD_ALLOW_LOOPBACK_BYPASS=0` and use an ingress in front.

### Scaling

`agentguard` is stateless beyond the on-disk audit log. Run multiple
replicas with a shared policy directory (read-only) and an audit log
volume per pod. Cache invalidation is per-pod; cache TTL bounds the
staleness window.

## Routine operations

### Verify audit log integrity

```bash
agentguard audit verify --audit .audit/decisions.jsonl \
                       --secret-file .chain-secret
```

Exit code 0 on a clean chain; non-zero with a per-record error report.

### Rotate a chain secret

The chain is single-key; replacing the secret while reusing the same audit
path is unsupported. Startup verifies the active file and all matching
timestamped rotation siblings with the configured key, so keeping old-key
segments beside the new active path will fail closed. To rotate keys:

1. Quiesce audit writes and verify the current chain with the old secret.
2. Preserve the old active file, its rotation segments, `.chainid` sidecars,
   and old secret together in a read-only archive directory.
3. Configure a new audit path and new secret for subsequent records; update
   the server configuration and restart it.
4. Verify the new chain with the new secret and retain the old verification
   command and key under restricted access for the archived evidence.

Keep old-key segments outside the new path's rotation filename pattern.
Key rotation starts a separate chain; it does not rewrite or re-sign history.
File-size rotation with the same key preserves one continuous chain and is
verified across the timestamped segments automatically.

### Hot reload policy

The watcher polls `AGENTGUARD_STORE` every 500 ms. On any `*.cedar`
file change, a complete replacement authorizer is parsed and atomically
swapped only when valid; `policy_reload_total` increments on success.
Verify changes first with `agentguard validate --store <path>`.

`SIGHUP` (Unix only) forces an immediate reload without touching the
filesystem.

### JWKS rotation

The JWT validator refreshes its JWKS every
`AGENTGUARD_JWKS_REFRESH` seconds (default 30 s). On a 5xx / connect
error it retries up to 3 times with exponential backoff (250 ms / 500 ms
/ 1 s cap). On permanent failure the validator keeps the last-known
keys (graceful degradation).

### Drain on shutdown

`SIGTERM` triggers graceful shutdown — the server stops accepting new work
and waits for in-flight requests. The process supervisor must enforce the
hard drain deadline; the Kubernetes reference deployment uses a 30 s
termination grace period. `SIGINT` (Ctrl-C) does the same.

## Failure modes

### Audit log write fails

The `Authorization: ...` decision is computed, then `audit.append()`
runs. If append fails (disk full, read-only mount, chain tamper), the
handler returns 500 with body `"audit log unavailable"`. The decision
is NOT returned to the caller — an audit failure is an authorization
failure. Investigate immediately; the operator should:

1. Check disk space: `df -h`
2. Check audit log permissions: `ls -la .audit/`
3. Verify chain integrity: `agentguard audit verify`
4. If the log is corrupted beyond repair, archive the bad log and
   rotate to a fresh file.

### Policy reload fails

A bad policy file triggers a reload error but the server keeps running
with the previous last-known-good policy snapshot. A valid policy file
is parsed completely before the snapshot is atomically replaced; in-flight
requests finish against their existing snapshot. Validate changes with
`agentguard validate --store <path>` and monitor the policy reload metric.

### OTLP collector unreachable

The OTLP sink uses a simple inline circuit breaker: after 5
consecutive flush failures, emits short-circuit to `Ok(())` until the
next successful flush resets the counter. Telemetry events are
dropped (no disk buffer) — use a sidecar like Vector / Fluent Bit to
ship them durably.

### JWKS endpoint unreachable

The OIDC discovery + JWKS fetch is retried up to 3 times with
exponential backoff. After exhaustion, the service fails to start
(safe default — refuse to serve without an authoritative key set).
For HA, deploy behind a config that pre-loads a JWKS file.

### Memory pressure

`Metrics` cardinality is capped (4096 distinct label tuples per
label-keyed metric). Beyond the cap, new tuples are dropped with a
single `tracing::warn!`. If you see cardinality overflow warnings,
reduce label dimensionality (e.g. drop `tenant_id` from the
`decision_duration` metric and keep it on `decision_total` only).

## Audit log archival

The audit log is append-only JSONL. File-size rotation creates timestamped
siblings and a hidden `.chainid` sidecar for each segment. Archive the active
file, every timestamped sibling, and every matching sidecar as one directory
snapshot; do not rename or gzip individual segments before verification.

```bash
tar -czf /tmp/agentguard-audit.tar.gz .audit
mkdir -p /tmp/agentguard-audit-restore
tar -xzf /tmp/agentguard-audit.tar.gz -C /tmp/agentguard-audit-restore
agentguard audit verify \
    --audit /tmp/agentguard-audit-restore/.audit/decisions.jsonl \
    --secret-file .chain-secret
aws s3 cp /tmp/agentguard-audit.tar.gz \
    s3://<bucket>/agentguard/$(date +%Y/%m/%d)/audit-set.tar.gz
```

The complete extracted set is verifiable offline with `agentguard audit
verify`. Do not delete it before your retention period expires.

## Backup / restore

`agentguard` is stateless beyond the audit log + chain secret. To
restore a deployment:

1. Restore the complete `.audit` directory, including the active log, rotated
   segments, and hidden `.chainid` sidecars, without changing filenames.
2. Restore the matching chain secret file.
3. Verify with `agentguard audit verify --audit .audit/decisions.jsonl
   --secret-file .chain-secret` before starting the server.
4. Restart the server; readiness must remain false if verification fails.

Cache + metrics are in-memory and lost on restart; this is
intentional (no stale state across deploys).

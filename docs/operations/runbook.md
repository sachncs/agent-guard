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
| `AGENTGUARD_AUTH` | `--auth` | `disabled` | `disabled` or `apikey:<path>` |
| `AGENTGUARD_AUTH_KEY_FILE` | `--auth-key-file` | (required if `--auth apikey`) | API-key store |
| `AGENTGUARD_GRPC_LISTEN` | `--grpc-listen` | (empty → disabled) | gRPC listen address |
| `AGENTGUARD_ALLOW_LOOPBACK_BYPASS` | — | `0` | Allow auth-disabled on public listener |
| `AGENTGUARD_CACHE_TTL` | — | `60s` | Decision cache TTL (humantime) |
| `AGENTGUARD_CACHE_CAPACITY` | — | `10000` | Decision cache size |
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
3. Generate API keys for callers:
   ```bash
   agentguard keygen --prefix ag_live --output /etc/agentguard/keys.json
   ```
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

### Roll a chain secret

The chain is single-key. Rotation requires a service-side cache flush
because old records are signed under the old key:

1. Start a fresh audit log file with the new key.
2. Old records remain verifiable with the old key in offline tooling.
3. New requests land in the new log.

There is no in-place rotation; this matches tamper-evident audit log
semantics (you can prove the old chain, but you can't silently edit
it).

### Hot reload policy

The watcher polls `AGENTGUARD_STORE` every 500 ms. On any `*.cedar`
file change, the cache is invalidated and `policy_reload_total`
incremented. Verify with `agentguard validate --store <path>`.

`SIGHUP` (Unix only) forces an immediate reload without touching the
filesystem.

### JWKS rotation

The JWT validator refreshes its JWKS every
`AGENTGUARD_JWKS_REFRESH` seconds (default 30 s). On a 5xx / connect
error it retries up to 3 times with exponential backoff (250 ms / 500 ms
/ 1 s cap). On permanent failure the validator keeps the last-known
keys (graceful degradation).

### Drain on shutdown

`SIGTERM` triggers graceful shutdown with a 30 s drain timeout —
in-flight requests are allowed up to 30 s to complete, then the
process exits. `SIGINT` (Ctrl-C) does the same.

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

A bad policy file triggers `tracing::warn!` but the server keeps
running with the previous policy set. The cache is invalidated on
each reload attempt; new requests will evaluate against the new
(possibly failing) policy. If cedar rejects the new policy outright
every request returns 500; check `agentguard validate --store <path>`.

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

The audit log is append-only JSONL. To archive:

```bash
gzip .audit/decisions.jsonl.archived
aws s3 cp .audit/decisions.jsonl.archived.gz \
    s3://<bucket>/agentguard/$(date +%Y/%m/%d)/decisions.jsonl.gz
```

The archived file is still verifiable offline with `agentguard audit
verify`. Don't delete it before your retention period expires.

## Backup / restore

`agentguard` is stateless beyond the audit log + chain secret. To
restore a deployment:

1. Restore `.audit/decisions.jsonl` + `.audit/decisions.jsonl.chainid`.
2. Restore the chain secret file.
3. Restart the server.

Cache + metrics are in-memory and lost on restart; this is
intentional (no stale state across deploys).

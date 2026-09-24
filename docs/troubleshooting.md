# Troubleshooting

Start with the health and readiness endpoints, the server logs, and the audit
append error. A deny is a normal authorization result; a transport, policy, or
audit error must stop tool execution and be investigated separately.

## The server is not ready

Check `/healthz` and `/readyz`, then inspect the configured store, policy path,
secret file permissions, and listener address. In Kubernetes, inspect events
and confirm the pod can read the projected ConfigMap and Secret. Readiness must
remain false when the policy or durable audit path cannot be used.

## Requests return 401 or 403

Confirm the selected auth mode and credential source with
`agentguard-server --help`. Do not combine the `apikey:<path>` value with a
separate path incorrectly. For OIDC, verify issuer discovery, client
credentials, callback URL, clock skew, and configured admin claim values.

Authentication proves who is calling; it does not make a request permissible.
Inspect the Cedar principal, action, resource, context, and supplied entities.

## A policy edit did not apply

Check the reload signal/log and validate the complete bundle. Invalid edits
continue serving the last known-good snapshot. Embedded authorizers do not
watch files automatically; rebuild the application-owned authorizer.

## Audit append fails

Stop executing tools, preserve the error and current files, and check disk
capacity, ownership, locking, and the chain sidecar. Do not delete or truncate
the audit file to make readiness pass. Restore the last verified backup only
after preserving the incident evidence.

## Console sessions or rate limits fail

Production requires Redis-compatible shared stores for both features. Verify
the endpoint, credential, TLS/proxy policy, and network policy from the console
pod. The console intentionally fails closed when a required shared store is
unavailable; in-memory mode is for development and test only.

## Delegation appears to work but a tool still runs

Token minting and verification are primitives, not enforcement. The tool
adapter must verify the delegation and compare its scope with the requested
action/resource before invocation. Review the integration boundary and audit
the final decision.

If revocation checks report an error, do not fall back to local memory or skip
the check. Verify Redis reachability, TLS, credentials, memory pressure,
`maxmemory-policy noeviction`, and persistence/replication health. If state may
have been evicted or restored from a stale backup, disable delegated execution
until state is reconciled or rotate affected delegation signing keys and remove
their old verification keys; absence of a key in Redis cannot distinguish an
unrevoked token from a lost revocation record.

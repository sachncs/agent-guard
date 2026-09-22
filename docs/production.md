# Production deployment

AgentGuard's supported reference deployment is Docker on Kubernetes. The
repository ships a server image, a console image, and a minimal Kustomize
base under deploy/k8s. See the detailed [Kubernetes operations](kubernetes.md),
[console deployment](console.md), and [incident response](incident-response.md)
guides alongside this overview.

## Before deploying

1. Replace the example schema and policies in the agentguard-policies
   ConfigMap with reviewed policy files.
2. Create agentguard-secrets with a chain secret and agentguard-api-keys
   with the JSON API-key store expected by agentguard-server.
3. Create agentguard-console-env with the OIDC and session variables listed
   in frontend/README.md.
4. Put TLS at the ingress or service mesh. The PDP must not be exposed on a
   public network without authentication and encrypted transport.

The standalone PDP polls the API-key Secret content and reloads valid
rotations/revocations without a process restart. After an update is visible at
the mounted path it is checked every 250 ms; Kubernetes Secret projection
itself is eventually consistent and depends on kubelet sync/cache settings.
Invalid intermediate store content retains the last-known-good key set and is
logged; check the server logs after credential updates.

kubectl apply -k deploy/k8s
kubectl -n agentguard rollout status deploy/agentguard-pdp
kubectl -n agentguard rollout status deploy/agentguard-console

The supplied manifests intentionally use one PDP and one console replica.
Audit persistence is a ReadWriteOnce volume. Production console operation
requires the Redis-compatible session and rate-limit stores; memory mode is
development/e2e-only and never becomes an implicit production fallback.
Multi-replica PDP operation is outside the shipped contract until a coordinated
append-only audit backend is deployed.

## Upgrade and rollback

Build and tag both images with the same release version. Apply the manifests,
wait for readiness, then run an allow, deny, and audit verification smoke
test. Roll back with kubectl rollout undo if readiness or audit checks fail.
Keep the policy ConfigMap, secrets, and audit volume across application
upgrades. The full smoke-test, backup, and rollback procedure is in
[Kubernetes operations](kubernetes.md).

## Operational guarantees

- /healthz is liveness only.
- /readyz requires a loaded policy store and writable configured audit log.
- A configured audit append failure returns an error instead of allowing the
  decision to continue silently.
- A corrupted chained audit tail refuses startup instead of silently beginning
  a disconnected chain; restore or quarantine the damaged evidence first.
- The server stops accepting new work on SIGTERM and drains in-flight work;
  the deployment supervisor enforces the hard termination deadline.
- API-key authentication is required for non-loopback PDP listeners.
- The published PDP container defaults to API-key authentication; provide a
  populated key-store Secret before sending protected requests. Explicitly set
  `AGENTGUARD_AUTH=disabled` only for isolated local development or a smoke
  environment that cannot be reached by untrusted clients.

These guarantees depend on the adapter honoring decision == true. AgentGuard
cannot protect an execution path that bypasses the PDP or ignores a denial.

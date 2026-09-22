# Production deployment

AgentGuard's supported reference deployment is Docker on Kubernetes. The
repository ships a server image, a console image, and a minimal Kustomize
base under deploy/k8s.

## Before deploying

1. Replace the example schema and policies in the agentguard-policies
   ConfigMap with reviewed policy files.
2. Create agentguard-secrets with a chain secret and agentguard-api-keys
   with the JSON API-key store expected by agentguard-server.
3. Create agentguard-console-env with the OIDC and session variables listed
   in frontend/README.md.
4. Put TLS at the ingress or service mesh. The PDP must not be exposed on a
   public network without authentication and encrypted transport.

kubectl apply -k deploy/k8s
kubectl -n agentguard rollout status deploy/agentguard-pdp
kubectl -n agentguard rollout status deploy/agentguard-console

The supplied manifests intentionally use one PDP and one console replica.
Audit persistence is a ReadWriteOnce volume and the console's rate limiter
is process-local. Do not scale either deployment horizontally until a shared
rate-limit/session adapter is configured and audit storage is replaced with a
coordinated append-only service or partitioning strategy.

## Upgrade and rollback

Build and tag both images with the same release version. Apply the manifests,
wait for readiness, then run an allow, deny, and audit verification smoke
test. Roll back with kubectl rollout undo if readiness or audit checks fail.
Keep the policy ConfigMap and audit volume across application upgrades.

## Operational guarantees

- /healthz is liveness only.
- /readyz requires a loaded policy store and writable configured audit log.
- A configured audit append failure returns an error instead of allowing the
  decision to continue silently.
- The server exits on SIGTERM after a bounded drain period.
- API-key authentication is required for non-loopback PDP listeners.

These guarantees depend on the adapter honoring decision == true. AgentGuard
cannot protect an execution path that bypasses the PDP or ignores a denial.

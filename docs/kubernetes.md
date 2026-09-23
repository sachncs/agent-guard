# Kubernetes operations

This is the supported production deployment path: build the pinned Docker
images, deploy the PDP and console with the Kustomize base, terminate TLS at a
trusted ingress, and operate policy and audit storage as managed state.

## Prerequisites

- Kubernetes 1.28 or newer and Kustomize v5.
- A registry reachable by the cluster.
- A `ReadWriteOnce` persistent volume for the PDP audit log.
- A TLS ingress or service mesh. The checked-in Services are intentionally
  internal cluster services.
- A plan for encrypting and restricting the in-cluster console-to-PDP hop.
  The console currently calls the PDP Service over plain HTTP; TLS at the
  external ingress does not encrypt this internal connection. For production,
  use a service mesh that enforces mTLS between the console and PDP workloads,
  or explicitly accept the cluster-network trust boundary and restrict the
  PDP Service to approved callers with a CNI-enforced NetworkPolicy. A
  NetworkPolicy limits reachability but does not encrypt traffic. Apply
  environment-specific ingress and egress policies in an overlay: the console
  also needs access to the configured identity provider and Redis endpoint,
  plus cluster DNS.
- An operator-managed Redis-compatible endpoint for console rate limiting when
  running more than one console replica.

## Build and publish

Use one immutable release tag for both images. Do not deploy `latest`:

```bash
export VERSION=0.2.0
export REGISTRY=registry.example.com/security
docker build --pull -t "$REGISTRY/agentguard-server:$VERSION" .
docker build --pull -t "$REGISTRY/agentguard-console:$VERSION" -f frontend/Dockerfile .
docker push "$REGISTRY/agentguard-server:$VERSION"
docker push "$REGISTRY/agentguard-console:$VERSION"
```

The images run as non-root users and expose `/healthz` and `/readyz` on the
PDP. Kubernetes enforces a 30-second termination grace period while the
server drains in-flight requests. The PDP image includes the `agentguard` CLI
for audit-chain verification. Scan both images before promotion.
Both pods set `fsGroup: 10001` with `fsGroupChangePolicy: OnRootMismatch` so
the non-root PDP can create and append its audit file on a newly provisioned
volume. Confirm that the selected CSI driver honors Kubernetes fsGroup
ownership handling; if it does not, provision the volume with group `10001`
and writable group permissions before deployment. The console uses the same
UID and mounts the audit directory read-only.

## Secrets and policy state

Create secrets outside Git. The API-key file must contain the serialized
`ApiKeyStore` format; it must not contain raw API-key secrets or passwords.

```bash
kubectl -n agentguard create secret generic agentguard-secrets \
  --from-file=chain-secret=./.chain-secret
kubectl -n agentguard create secret generic agentguard-api-keys \
  --from-file=keys.json=./keys.json
kubectl -n agentguard create secret generic agentguard-delegation-key \
  --from-file=delegation.key=./delegation.key
kubectl -n agentguard create secret generic agentguard-console-env \
  --from-literal=AGENTGUARD_OIDC_ISSUER='https://idp.example.com/realms/acme' \
  --from-literal=AGENTGUARD_OIDC_CLIENT_ID='agentguard-console' \
  --from-literal=AGENTGUARD_OIDC_CLIENT_SECRET='replace-me' \
  --from-literal=AGENTGUARD_SESSION_SECRET='replace-with-at-least-32-random-chars' \
  --from-literal=AGENTGUARD_SESSION_STORE='redis' \
  --from-literal=AGENTGUARD_SESSION_REDIS_URL='https://redis.example.com' \
  --from-literal=AGENTGUARD_SESSION_REDIS_TOKEN='replace-me' \
  --from-literal=AGENTGUARD_TRUST_PROXY_HEADERS='1' \
  --from-literal=AGENTGUARD_ADMIN_VALUES='security-admins' \
  --from-literal=AGENTGUARD_RATE_LIMIT_STORE='redis' \
  --from-literal=AGENTGUARD_RATE_LIMIT_REDIS_URL='https://redis.example.com' \
  --from-literal=AGENTGUARD_RATE_LIMIT_REDIS_TOKEN='replace-me'
```

The PDP polls the projected API-key Secret contents and applies a valid
rotation or revocation without a process restart. Once the updated bytes are
visible in the container, they are checked every 250 ms. Kubelet projection is
eventually consistent and its delay depends on the node's sync/cache settings,
so do not assume a one-second end-to-end revocation bound. Mount the Secret as
a directory (as in the base manifest), not with `subPath`. Invalid
intermediate JSON is logged and the last-known-good key set remains active
until a valid snapshot is detected.

The console production config requires the trusted-proxy flag. The ingress
must remove any incoming `X-Forwarded-For` value and replace it with exactly
one validated client address; do not enable the flag when the console can be
reached directly by untrusted clients.

The delegation key is a persistent Ed25519 private key used by the admin
console when issuing grants. Rotate it as a credential, publish the matching
trusted public key to verifiers, and never use an ephemeral key in production.

The checked-in ConfigMap contains the valid starter schema and an empty
deny-by-default policy so a fresh deployment can become ready safely. Replace
both with reviewed schema and policies before enabling traffic. Treat a policy
change as a release: validate it, review the diff, apply it, observe the reload
metric, and run representative allow and deny requests.

## Deploy

Set image references in an overlay or with `kustomize edit set image`, then:

```bash
kubectl apply -k deploy/k8s
kubectl -n agentguard rollout status deployment/agentguard-pdp
kubectl -n agentguard rollout status deployment/agentguard-console
kubectl -n agentguard get pods,svc,pvc
```

Put an ingress in front of the console and PDP only when the PDP API-key
secret, external TLS policy, network policy, and request-size/timeouts are
configured. External TLS alone is insufficient: the console-to-PDP hop uses
plain HTTP in the reference configuration. Enforce mesh mTLS for that hop, or
document and isolate the trusted cluster-network boundary with a CNI-enforced
policy that permits only the console workload to reach the PDP Service. The
reference manifests do not install a NetworkPolicy because allowed ingress,
identity-provider, Redis, and DNS peers are environment-specific. Do not expose
the plaintext optional gRPC listener outside a trusted loopback or private
network; the reference manifests do not enable it.

## Smoke test and rollout gate

Before routing traffic, verify:

1. `/healthz` is live and `/readyz` is ready only after policy and audit state
   are available.
2. An authenticated request returns the expected allow decision.
3. A denied request remains denied.
4. The audit file grows and verification succeeds with the chain secret:

   ```bash
   kubectl -n agentguard exec deployment/agentguard-pdp -- agentguard audit verify \
     --audit /var/lib/agentguard/audit/decisions.jsonl \
     --secret-file /etc/agentguard/secrets/chain-secret
   ```
5. A PDP pod terminates cleanly and becomes ready after restart.
6. Console login, viewer access, admin access, PDP failure handling, and rate
   limiting behave as expected.

CI runs the PDP portion automatically in a disposable kind cluster. To run the
same contract locally, start kind and run from the repository root:

```bash
docker build --tag agentguard-server:smoke .
docker tag agentguard-server:smoke agentguard-server:smoke-rollback
kind load docker-image agentguard-server:smoke
kind load docker-image agentguard-server:smoke-rollback
./scripts/k8s-smoke.sh
```

The smoke script binds the disposable PDP to the pod network and disables
authentication only inside the isolated test namespace; the production
manifest keeps API-key authentication and must remain behind TLS/network
controls.

## Backups, upgrades, and rollback

Back up the audit file, its `.chainid` sidecar, the chain secret, the API-key
store, and the exact schema/policy bundle together. Test restore into an
isolated namespace; a backup without its chain secret cannot verify a chained
log.

For an upgrade, publish immutable images, apply the image change, wait for
readiness, and run the smoke test. If readiness, authorization, or audit
verification fails, stop traffic and run:

```bash
kubectl -n agentguard rollout undo deployment/agentguard-pdp
kubectl -n agentguard rollout undo deployment/agentguard-console
kubectl -n agentguard rollout status deployment/agentguard-pdp
```

Keep the policy ConfigMap, secrets, and audit PVC across application rollbacks.
The reference PDP deployment uses one replica because the audit writer is
file-backed. The console image includes the CLI used by its audit and
delegation routes and mounts policy/audit state read-only. Its required pod
affinity keeps it on the same node as the PDP so the `ReadWriteOnce` audit
volume remains attachable. Multi-replica PDP operation requires a coordinated
append-only audit design and is outside the shipped production contract.

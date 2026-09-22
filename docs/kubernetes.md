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

The images run as non-root users, expose `/healthz` and `/readyz` on the PDP,
and use bounded termination. Scan both images before promotion.

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
  --from-literal=AGENTGUARD_ADMIN_VALUES='security-admins' \
  --from-literal=AGENTGUARD_RATE_LIMIT_REDIS_URL='https://redis.example.com' \
  --from-literal=AGENTGUARD_RATE_LIMIT_REDIS_TOKEN='replace-me'
```

The delegation key is a persistent Ed25519 private key used by the admin
console when issuing grants. Rotate it as a credential, publish the matching
trusted public key to verifiers, and never use an ephemeral key in production.

Replace `deploy/k8s/configmap.yaml` with reviewed schema and policies. Treat a
policy change as a release: validate it, review the diff, apply it, observe
the reload metric, and run representative allow and deny requests.

## Deploy

Set image references in an overlay or with `kustomize edit set image`, then:

```bash
kubectl apply -k deploy/k8s
kubectl -n agentguard rollout status deployment/agentguard-pdp
kubectl -n agentguard rollout status deployment/agentguard-console
kubectl -n agentguard get pods,svc,pvc
```

Put an ingress in front of the console and PDP only when the PDP API-key
secret, TLS policy, network policy, and request-size/timeouts are configured.
Do not expose the plaintext optional gRPC listener outside a trusted loopback
or private network; the reference manifests do not enable it.

## Smoke test and rollout gate

Before routing traffic, verify:

1. `/healthz` is live and `/readyz` is ready only after policy and audit state
   are available.
2. An authenticated request returns the expected allow decision.
3. A denied request remains denied.
4. The audit file grows and `agentguard audit verify` succeeds with the chain
   secret.
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

The smoke script uses loopback and disabled authentication only inside the
disposable test cluster; the production manifest keeps API-key authentication.

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

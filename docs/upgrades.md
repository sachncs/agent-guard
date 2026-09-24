# Upgrades and rollback

AgentGuard releases are immutable artifacts. Use a versioned tag when building
and publishing, but deploy the registry image digest rather than relying on
the tag being immutable. Never deploy `latest`. Keep the image digests, policy
bundle version, schema, configuration, and migration notes together.

## Before upgrading

- Read the release notes and compatibility policy.
- Run the target image against a copy of the policy and audit store.
- Verify the configured Redis-compatible session and rate-limit stores.
- Export and verify the current audit chain.
- Take a policy and audit backup and record the current image digest.
- Confirm the Kubernetes rollback target is still available.

## Kubernetes rollout

If this is a new environment, first copy
`deploy/k8s/overlays/production/kustomization.yaml.example` to
`deploy/k8s/overlays/production/kustomization.yaml` and replace its registry
names and digest placeholders. For an existing environment, update both image
digests in that production Kustomize overlay. Review the resulting diff, then
wait for readiness:

```sh
kubectl -n agentguard apply -k deploy/k8s/overlays/production
kubectl -n agentguard rollout status deployment/agentguard-pdp
kubectl -n agentguard rollout status deployment/agentguard-console
```

Run an allow, deny, audit append, and console-to-PDP check after the rollout.
Do not route traffic to a pod that is only live; readiness must be green.

## Rollback

```sh
kubectl -n agentguard rollout history deployment/agentguard-pdp
kubectl -n agentguard rollout undo deployment/agentguard-pdp
kubectl -n agentguard rollout status deployment/agentguard-pdp
```

If a policy change caused the incident, restore the last known-good policy
bundle before or alongside the image rollback. Do not delete the audit PVC.
Preserve the failed pod logs, image digest, policy diff, and audit export for
the incident record.

The release is not considered upgraded until the smoke checks pass and the
rollback target is documented. See [Kubernetes operations](kubernetes.md) and
the [incident response guide](incident-response.md).

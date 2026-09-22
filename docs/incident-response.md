# Incident response

AgentGuard can make a decision boundary explicit, but it cannot repair an
application that bypasses the boundary. During an incident, stop tool
execution first, preserve evidence, and then diagnose the control plane.

## Immediate containment

1. Stop or isolate the affected agent and revoke its upstream credentials.
2. Preserve the audit file, `.chainid` sidecar, chain secret, policy bundle,
   deployment manifest, and relevant metrics/logs.
3. Restrict PDP network access to known callers and confirm API-key or ingress
   authentication is active.
4. If policy integrity is uncertain, fail closed and restore a reviewed policy
   bundle rather than editing the live file repeatedly.

## Triage

Check `/healthz`, `/readyz`, PDP error metrics, policy reload failures, audit
append errors, and the console's OIDC/PDP logs. Compare the current policy
bundle hash and deployment image digest with the release record. Verify the
audit chain offline:

```bash
agentguard audit verify --audit .audit/decisions.jsonl \
  --secret-file .chain-secret
```

An audit verification failure means the original evidence must be preserved;
do not overwrite it while attempting repair. Rotate to a new file only after
the failed file has been copied to controlled evidence storage.

## Common decisions

- **PDP unavailable:** stop tool execution; do not fall back to local allow.
- **Audit append failure:** the server returns an error for configured audit;
  investigate storage and disk pressure before restoring traffic.
- **Policy reload failure:** the last known-good snapshot continues serving;
  validate and atomically replace the policy bundle.
- **Compromised chain secret:** treat all records signed with it as suspect,
  rotate the secret and record the exact cutover boundary.
- **Console compromise:** revoke the OIDC client/session secret, invalidate
  admin access at the IdP, rotate PDP credentials, and inspect delegation
  issuance records.

Document timeline, scope, decisions, evidence hashes, and follow-up controls.
Report security vulnerabilities privately using [SECURITY.md](../SECURITY.md),
not in a public issue.

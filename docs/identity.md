# Identity and scoped delegation

Authentication identifies a caller. Authorization decides what that caller may
do. AgentGuard keeps those operations separate so an untrusted model cannot
choose a stronger identity or security context.

## Standalone PDP authentication

The server supports disabled authentication for local development and API-key
bearer validation for decision routes. The persisted `ApiKeyStore` stores
Argon2id hashes with expiry and revocation state. Protected HTTP and gRPC
evaluation requires a key bound to one `User` or `Agent` subject and the
`authorize` scope (or `*`). The submitted subject must match the key. A key's
optional tenant is injected as trusted request/audit metadata; it is not itself
a Cedar policy attribute, so tenant isolation must still be encoded using
trusted entities and policy inputs. A conflicting caller-supplied
`context.tenant_id` is rejected. Unbound legacy keys remain
readable for migration but cannot authorize standalone evaluations. Rotate or
reissue them as bound keys before enabling this enforcement.

Trusted policy consoles that must simulate different subjects can use the
explicit `authorize:any` scope. The key must still be bound to a service
identity; the scope permits its holder to submit a different evaluation
subject. Treat this as a privileged impersonation capability: store it only in
the console's server-side secret store, never expose it to browsers, restrict
console access with OIDC/RBAC, and prefer tenant-bound service identities.
Ordinary `authorize` keys remain identity-bound, and wildcard `*` does not
implicitly grant `authorize:any`.

Argon2id verification runs on Tokio's blocking pool and is capped at two
concurrent verifications per process to bound CPU and memory use. Requests
with missing or structurally malformed bearer credentials are rejected before
acquiring a verification slot. If all slots are busy, protected HTTP requests
receive `503 Service Unavailable` and gRPC requests receive `UNAVAILABLE`; the
caller should retry with bounded backoff. Put network-level rate limiting at
the ingress as an additional control against sustained credential guessing.
The gRPC evaluation transport also caps decoded requests at 64 KiB, matching
the HTTP request-body budget.

Create keys through the operator CLI, assigning only the narrow scope and
identity required by that integration:

```sh
agentguard api-key create --key-store ./keys.json \
  --subject-type Agent --subject-id research --tenant-id tenant-a \
  --scope authorize --ttl-seconds 2592000
agentguard api-key list --key-store ./keys.json
agentguard api-key revoke --key-store ./keys.json KEY_ID
```

Creation prints the raw secret once, after the hashed record has been saved;
listing omits secret hashes and raw secrets. Protect the store as a secret and
mount it read-only into the PDP. Never let an untrusted caller choose the
identity bound to its own credential. `metrics:read` gates the metrics
endpoint. API-key scopes gate endpoint capabilities; Cedar policies still make
the resource/action authorization decision.

The standalone server polls the key-store content and applies valid file
updates (including Kubernetes projected Secret updates) without a restart.
Once new bytes are visible at the mounted path, the server checks them every
250 ms. Kubernetes projection itself is eventually consistent and depends on
the kubelet's sync/cache configuration; do not promise an end-to-end one-second
revocation bound. Mount the Secret as a directory, not with `subPath`, so
projected updates can become visible. Invalid or partially projected JSON is
logged and the last-known-good key set remains active; correct the file and
let the next content update trigger another reload.

Do not expose a listener with disabled authentication. For a non-loopback
listener, configure `AGENTGUARD_AUTH=apikey:<path>` or the equivalent CLI flags,
then terminate TLS at a trusted ingress or service mesh.

## Library identity validators

`agentguard-auth` provides library primitives for JWT/JWKS validation, OIDC
discovery, DPoP proof validation, and feature-gated SPIFFE/SPIRE workload
identity. These are not automatically enabled server authentication modes.
Embedding applications must invoke the validator, map the validated claims to a
`User` or `Agent` Cedar principal, and pass only trusted facts to evaluation.

`DpopVerifier` replay tracking is process-local. Its default tracker retains
up to 262,144 live proof identifiers; callers may choose another positive cap
with `JtiTracker::with_capacity`. At capacity, new proofs fail closed with
`DpopCapacityExceeded` until old entries expire. The tracker does not share
replay state across processes and loses it on restart, so deployments requiring
cluster-wide replay protection can inject a shared implementation of
`DpopReplayStore` or `AsyncDpopReplayStore`. Both must atomically retain each
accepted JTI across the deployment scope and fail closed on storage errors.
Synchronous implementations must not perform blocking remote I/O on an async
runtime worker. For remote stores, implement `AsyncDpopReplayStore`, construct the verifier with
`DpopVerifier::new_async`, and call `verify_async`; this awaits the storage
operation without blocking the worker. The bundled `JtiTracker` remains
process-local, and no shared backend is included in the standalone PDP
contract.

## Console OIDC

The optional Next.js console uses OIDC Authorization Code + PKCE. Every signed
session is at least a viewer session. Admin access is granted only when a
configured claim contains an explicitly configured admin value. Missing OIDC,
session, or production shared-store configuration fails closed with `503`.
See [console deployment](console.md) for the complete environment contract.

## Delegation is a separate enforcement boundary

The CLI and Rust library can mint and verify Ed25519 JWS grants containing an
issuer, subject, audience, expiry, allowed actions, resource patterns, and
optional actor/constraint claims:

```sh
agentguard delegate \
  --from 'Agent::"research"' \
  --to 'Agent::"summarizer"' \
  --actions ToolCall::repo_read \
  --resources 'Repository::demo' \
  --ttl 300 --key-file delegation.key --out delegation.jws
```

Signature verification alone is not authorization. A consuming adapter must:

1. authorize the parent before it issues a grant;
2. verify the signature, audience, key identity, and time claims;
3. enforce action/resource/constraint scope and any sender binding;
4. evaluate the effective Cedar policy; and
5. apply revocation or replay state when the application requires it.

AgentGuard does not ship an OAuth token-exchange endpoint or a delegation-token
revocation service. RFC 8693-style actor claims are primitives for an adapter,
not a claim that the standalone PDP enforces parent authority automatically.

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

Create keys through `ApiKeyStore::create_bound`, assigning only the narrow
scope and identity required by that integration. Keys should be provisioned
through a trusted administrative path; never let an untrusted caller choose
the identity bound to its own credential. `metrics:read` gates the metrics
endpoint. API-key scopes gate endpoint capabilities; Cedar policies still make
the resource/action authorization decision.

Do not expose a listener with disabled authentication. For a non-loopback
listener, configure `AGENTGUARD_AUTH=apikey:<path>` or the equivalent CLI flags,
then terminate TLS at a trusted ingress or service mesh.

## Library identity validators

`agentguard-auth` provides library primitives for JWT/JWKS validation, OIDC
discovery, DPoP proof validation, and feature-gated SPIFFE/SPIRE workload
identity. These are not automatically enabled server authentication modes.
Embedding applications must invoke the validator, map the validated claims to a
`User` or `Agent` Cedar principal, and pass only trusted facts to evaluation.

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

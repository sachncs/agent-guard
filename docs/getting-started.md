# Getting started

## 5-minute tutorial: protect an agent's tool calls

### 1. Install

```bash
cargo install --path /path/to/agentguard/crates/agentguard-cli
which agentguard
```

### 2. Create a project

```bash
mkdir my-agent && cd my-agent
agentguard init --name acme
```

This creates:

```
.agentguard/
├── schema.cedarschema
└── policies/
    ├── 10_admin.cedar
    └── 20_agents.cedar
```

The generated policies are intentionally permissive development examples:
the admin rule grants a global superuser and the agent rule permits every
declared tool. Replace them with reviewed, least-privilege rules before using
real credentials or deploying beyond loopback.

### Optional: run a local HTTP PDP

The `agentguard` CLI evaluates in-process. For a local HTTP integration test,
install the separate `agentguard-server` binary after initializing the store.
Its gRPC mirror is optional, repository-defined, plaintext, and not a
standardized AuthZEN gRPC protocol. Building it requires `protoc` (for example,
`apt install protobuf-compiler` or `brew install protobuf`).

This example is loopback-only development configuration. It uses a local
random chain secret and disables PDP authentication only on the loopback
listener; use the [production deployment guide](production.md) for remote or
production deployments.

```bash
cargo install --path /path/to/agentguard/crates/agentguard-server
umask 077
openssl rand -hex 32 > .chain-secret
export AGENTGUARD_LISTEN="tcp://127.0.0.1:8443"
export AGENTGUARD_STORE="$PWD/.agentguard"
export AGENTGUARD_AUDIT="$PWD/.audit/decisions.jsonl"
export AGENTGUARD_CHAIN_SECRET="$PWD/.chain-secret"
export AGENTGUARD_AUTH=disabled
agentguard-server
```

In another terminal, confirm readiness and make a real decision using the
generated starter agent policy:

```bash
curl --fail-with-body http://127.0.0.1:8443/readyz
curl --fail-with-body http://127.0.0.1:8443/access/v1/evaluation \
  -H 'content-type: application/json' \
  -d '{"subject":{"type":"Agent","id":"research"},"action":{"type":"Action","id":"ToolCall::repo_read"},"resource":{"type":"Repository","id":"demo"},"context":{"repo":"demo","session":{"ip":"127.0.0.1"}}}'
```

The response must contain `"decision":true`. The server writes the decision
to the configured chained audit log before returning it. Available endpoints:

- `POST /access/v1/evaluation` — single decision (AuthZEN draft).
- `POST /access/v1/evaluations` — batch (cap 100 per call).
- `GET /healthz` / `/readyz` — liveness and readiness.
- `GET /metrics` — Prometheus-text snapshot.
- Optional gRPC: set `AGENTGUARD_GRPC_LISTEN=127.0.0.1:9443`.

### 3. Edit the schema to match your tools

`.agentguard/schema.cedarschema` already declares common tools
(`send_email`, `read_doc`, `write_doc`, `repo_read`, `repo_write`,
`shell_exec`, `web_fetch`). Add or remove as needed:

```cedarschema
action "ToolCall::my_custom_tool" appliesTo {
  principal: [User, Agent],
  resource: [Document],
  context: { foo: String, session: Session }
};
```

### 4. Write a least-privilege policy

The generated `10_admin.cedar` and `20_agents.cedar` files grant broad
development access. Replace them before trying the SDK example; adding a
narrow rule alongside those defaults would not restrict their existing grants.
This policy allows Alice to send email only to her mailbox, and only with
MFA:

```bash
rm .agentguard/policies/10_admin.cedar .agentguard/policies/20_agents.cedar
cat > .agentguard/policies/10_alice_send_email.cedar <<'CEDAR'
permit (
  principal == User::"alice",
  action == Action::"ToolCall::send_email",
  resource == Mailbox::"alice@acme"
) when {
  context.session has mfa &&
  context.session.mfa == true
};
CEDAR
agentguard validate
```

Validation should report no errors. A different user, mailbox, action, or
request without verified MFA receives a deny.

### 5. Hook into your agent

The TypeScript SDK is the fastest path:

```typescript
import { Client, Principal, Action } from "agentguard";

const client = new Client({ store: ".agentguard" });

// Raises AuthorizationDenied on deny; call inside your tool handler.
client.check(
  Principal.user("alice"),
  Action.tool("send_email"),
  { entity_type: "Mailbox", uid: "alice@acme" },
  {
    args: { to: "[email protected]", subject: "Hello", body: "Hi Alice" },
    session: { mfa: true }
  }
);
```

The SDK is CLI-backed and evaluates against the local policy store; it does
not discover or call a remote PDP. The synchronous `Client.check` blocks the
Node.js event loop; use `Client.checkAsync` (or `authorizeAsync`) in
latency-sensitive or concurrent server handlers. Async CLI calls use the
configured timeout and per-client concurrency/output limits. The SDK does not
automatically intercept framework tools: call it in your tool handler, or
implement an adapter that guards every execution path.

For Strands Agents (TypeScript), see
[`examples/strands-tool-authz`](../examples/strands-tool-authz/) — its
`guarded` wrapper calls the standalone AuthZEN PDP before each wrapped tool
callback and fails closed when the PDP denies or cannot be reached.

Prefer no SDK at all? Run `agentguard-server` and POST to
`/access/v1/evaluation` from any language — every decision still lands in
the audit log.

Only calls routed through the guard are authorized. Denials raise
`AuthorizationDenied`; make sure retries, alternate tool paths, and delegated
calls use the same enforcement boundary.

### 6. Test interactively

```bash
agentguard sim request.json
```

Where `request.json` looks like:

```json
{
  "principal": {"type": "agent", "uid": "research"},
  "action": {"tool": "repo_read"},
  "resource": {"entity_type": "Repository", "uid": "demo"},
  "context": {
    "args": {"repo": "demo"},
    "session": {"ip": "127.0.0.1"}
  }
}
```

### 7. Inspect decisions

```bash
agentguard log tail --n 20
```

```
14:23:12 ✓ ALLOW alice send_email alice@acme
14:23:08 ✗ DENY  bob   send_email alice@acme
14:22:55 ✓ ALLOW Agent::"research" send_email alice@acme
```

### 8. Run as a server for HTTP integrations

`agentguard-server` exposes a separate AuthZEN HTTP API over the same core
engine. CLI `authorize` and `sim` always evaluate in-process; setting
`AGENTGUARD_URL` does not turn them into remote clients. Use an HTTP client or
an adapter such as the Strands example to call a remote PDP.

The loopback HTTP example is in [Optional: run a local HTTP PDP](#optional-run-a-local-http-pdp).
For a remote or production PDP, do not use `AGENTGUARD_AUTH=disabled`:
configure API-key authentication and TLS as described in the
[production deployment guide](production.md).

### 9. Caching + policy changes

The standalone server enables the decision cache by default (60 s / 10 k
entries). Set `AGENTGUARD_CACHE_TTL`, `AGENTGUARD_DENY_CACHE_TTL`, or
`AGENTGUARD_CACHE_CAPACITY` before startup to override those values. The server
auto-reloads the policy directory on file change; on Unix,
`SIGHUP` forces an immediate reload.

### 10. Observability

`GET /metrics` returns Prometheus text. Wire to your scrape
target — the prefix is `agentguard_*`:

```text
agentguard_decision_total{effect="allow",policy_id="p0",action="ToolCall::send_email",tenant_id=""} 1
agentguard_decision_duration_seconds_bucket{action="ToolCall::send_email",tenant_id="",le="0.001"} 1
agentguard_cache_hit_total 1
agentguard_policy_reload_total 3
```

## Adding multi-agent delegation

When your agent calls a sub-agent, mint a scoped token:

```typescript
import { Client } from "agentguard";

const client = new Client({ store: ".agentguard" });

const token = client.delegate(
  'Agent::"research"',
  'Agent::"summarizer"',
  ["ToolCall::send_email"],
  ["Mailbox::alice*"],
  300
);

// Pass `token` to the sub-agent
subAgent.runWithCredentials({ agentguardToken: token });
```

The token is a signed grant, not automatic enforcement. The receiving
application must verify its signature, expiry, audience, and sender binding,
then enforce its action/resource scopes and confirm the parent was allowed to
delegate them before the sub-agent executes a tool. The standalone PDP does not
automatically consume delegation tokens.

## Writing Cedar policies

See the [Cedar docs](https://docs.cedarpolicy.com/) for the full syntax. The
patterns you'll use most:

```cedar
// Allow alice to do anything.
permit (principal == User::"alice", action, resource);

// Allow members of a group.
permit (principal in Group::"admins", action, resource);

// Allow agents of a certain type to act on a resource owned by their parent user.
permit (
  principal is Agent,
  action,
  resource.owner == principal.parent
) when {
  principal has parent && principal.parent is User
};

// Conditional allow — only from the corporate network.
permit (principal, action, resource) when {
  context.session.ip like "10.*"
};

// Deny unless MFA.
forbid (principal, action, resource) when {
  !(context.session has mfa && context.session.mfa == true)
};
```

## Next steps

- [Architecture](architecture.md) — how it all fits together.
- [Frontend console](../frontend/) — dashboard, policy simulator, delegation UI.
- [Strands example](../examples/strands-tool-authz/) — guard Strands tool calls via the PDP.
- [Cedar docs](https://docs.cedarpolicy.com/) — the policy language.

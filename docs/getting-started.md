# Getting started

## 5-minute tutorial: protect an agent's tool calls

### 1. Install

```bash
cargo install --path /path/to/agentguard/crates/agentguard-cli
which agentguard
```

### 1b. (Optional) Run the server

The `agentguard` CLI is a self-contained PDP (it loads policies and
authorizes decisions in-process). For multi-process or networked
deployments, run the `agentguard-server` binary which exposes the
same engine over AuthZEN HTTP + gRPC:

```bash
cargo install --path /path/to/agentguard/crates/agentguard-server

export AGENTGUARD_LISTEN="tcp://127.0.0.1:8443"
export AGENTGUARD_STORE=".agentguard"
export AGENTGUARD_AUDIT=".audit/decisions.jsonl"
export AGENTGUARD_AUTH="apikey:/etc/agentguard/keys.json"   # or "disabled"
agentguard-server
```

Available endpoints:

- `POST /access/v1/evaluation` — single decision (AuthZEN draft).
- `POST /access/v1/evaluations` — batch (cap 100 per call).
- `GET /healthz` / `/readyz` — Kubernetes probes.
- `GET /metrics` — Prometheus-text snapshot.
- gRPC: `agentguard.v1.AccessEvaluation` (enable with
  `AGENTGUARD_GRPC_LISTEN=0.0.0.0:9443`).

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

### 4. Write policies

Cedar is deny-by-default. Add `permit` rules to allow specific actions:

```cedar
// alice can read her own docs.
permit (
  principal == User::"alice",
  action == Action::"ToolCall::read_doc",
  resource.owner == principal
);

// agents can fetch web pages from anywhwere
permit (
  principal is Agent,
  action == Action::"ToolCall::web_fetch",
  resource
);

// sensitive tools require MFA
forbid (
  principal,
  action in [Action::"ToolCall::send_email", Action::"ToolCall::shell_exec"],
  resource
) when {
  !(context.session.mfa == true)
};
```

Validate:

```bash
agentguard validate
```

### 5. Hook into your agent

The Python SDK + LangChain middleware is the fastest path:

```python
from langchain.agents import initialize_agent, AgentType
from langchain_openai import OpenAI
from langchain_community.tools import DuckDuckGoSearchRun
from agentguard_langchain import GuardConfig, GuardedTool, Principal

search = GuardedTool(
    DuckDuckGoSearchRun(),
    GuardConfig(
        store=".agentguard",
        principal_factory=lambda _: Principal.user("alice"),
    ),
)

agent = initialize_agent(
    tools=[search],
    llm=OpenAI(),
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
)
agent.run("...")
```

Every call to `search` is now authorized. Denials raise `PermissionError`.

### 6. Test interactively

```bash
agentguard sim request.json
```

Where `request.json` looks like:

```json
{
  "principal": {"type": "user", "uid": "alice"},
  "action": {"tool": "send_email"},
  "resource": {"entity_type": "Mailbox", "uid": "alice@acme"},
  "context": {
    "args": {"to": "[email protected]", "subject": "hi", "body": "yo"},
    "session": {"ip": "10.0.0.1", "user_agent": "...", "mfa": true, "ts": 0}
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

### 8. Run as a server (multi-process / networked)

`agentguard-server` exposes the same engine over AuthZEN HTTP +
gRPC. The CLI auto-detects a running server when `AGENTGUARD_URL`
is set and shells out to it; otherwise it falls back to in-process
evaluation.

```bash
export AGENTGUARD_URL=http://localhost:8443/access/v1/evaluation
agentguard authorize request.json
```

### 9. Caching + hot reload

`AGENTGUARD_CACHE_TTL=60s AGENTGUARD_CACHE_CAPACITY=10000` turn on
the decision cache (default 60 s / 10 k entries). The server
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

```python
from agentguard import Client

client = Client(store=".agentguard")

token = client.delegate(
    from_principal='Agent::"research"',
    to='Agent::"summarizer"',
    actions=["ToolCall::send_email"],
    resources=["Mailbox::alice*"],
    ttl_seconds=300,
)

# Pass `token` to the sub-agent
sub_agent.run_with_credentials(..., credentials={"agentguard_token": token})
```

The sub-agent's authorization engine verifies the token before evaluating any
request.

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
  !(context.session.mfa == true)
};
```

## Next steps

- [Architecture](architecture.md) — how it all fits together.
- [Examples](../examples/) — basic authz, multi-agent delegation, NL policy gen.
- [Cedar docs](https://docs.cedarpolicy.com/) — the policy language.
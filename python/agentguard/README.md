# agentguard — Python SDK

Thin, ergonomic Python interface over the `agentguard` CLI.

## Install

```bash
# Inside this repo, install the CLI binary first:
cargo install --path crates/agentguard-cli

# Then install the SDK:
pip install python/agentguard
```

## Quick start

```python
from agentguard import Client, Principal, AgentAction, Resource, Context

client = Client(store=".agentguard")

decision = client.authorize(
    Principal.user("alice"),
    AgentAction.tool("send_email"),
    Resource("Mailbox", "alice@acme"),
    Context(args={"to": "[email protected]", "subject": "hi", "body": "yo"}),
)

if decision.allow:
    # proceed
else:
    # surface denial reason
```

## Delegation

```python
from agentguard import Client

client = Client(store=".agentguard")
token = client.delegate(
    from_principal="Agent::research",
    to="Agent::summarizer",
    actions=["ToolCall::send_email"],
    resources=["Mailbox::*"],
    ttl_seconds=600,
)
print(token)  # compact "<payload>.<sig>.<kid>"

claims = client.verify(token)
```
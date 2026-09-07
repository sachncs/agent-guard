# Strands tool-call authorization with agentguard (TypeScript)

A [Strands Agents](https://github.com/strands-agents/sdk-typescript) demo where
every tool call is authorized by agentguard's Cedar policies before the tool
runs — fail-closed, via the OpenID AuthZEN evaluation API.

## How it works

`src/guard.ts` exports:

- `AgentGuard` — talks to the PDP at `POST /access/v1/evaluation`
  (`subject` / `action: ToolCall::<name>` / `resource` / `context.args`).
- `guarded(guard, config)` — wraps a Strands `tool()` config so the callback
  only runs when the PDP says `decision: true`. Denials (and PDP outages)
  surface to the model as an error tool result, so the agent can explain and
  adapt instead of crashing.

## Run it

```sh
# 1. Build + install the CLI, initialize a policy store
cargo install --path crates/agentguard-cli
agentguard init --name acme

# 2. Start the AuthZEN PDP (default http://127.0.0.1:8443)
agentguard serve

# 3. Give alice permission to search but not to send email
cat > ~/.config/agentguard/policies/30_strands.cedar <<'EOF'
permit(principal == User::"alice", action == Action::"ToolCall::web_search", resource);

forbid(principal == User::"alice", action == Action::"ToolCall::send_email", resource)
when { context.has_mfa != true };
EOF

# 4. Credentials for the demo model (Amazon Bedrock) and the user identity
export AWS_REGION=us-east-1
export AGENTGUARD_USER=alice

# 5. Run
pnpm --filter strands-tool-authz start
```

The agent searches the web (allowed) and then fails to send the email (denied),
with both decisions visible in `agentguard log`.

## Configuration

| Env var             | Purpose                                        | Default                  |
| ------------------- | ---------------------------------------------- | ------------------------ |
| `AGENTGUARD_URL`    | PDP base URL                                   | `http://127.0.0.1:8443`  |
| `AGENTGUARD_BEARER` | Bearer token if PDP auth is enabled            | –                        |
| `AGENTGUARD_USER`   | Principal id passed as `User::"<id>"`          | – (unset ⇒ all denied)   |
| `BEDROCK_MODEL_ID`  | Bedrock model id                               | Claude Sonnet 4          |

In production, resolve the principal from your request context instead of an
env var — pass a function to `new AgentGuard({ principal })`.

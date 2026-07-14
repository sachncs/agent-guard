# multi-agent-delegation

When an agent delegates work to a sub-agent, the sub-agent should receive a
**scoped subset** of the parent's permissions, time-boxed and revocable.

agentguard implements this with signed tokens containing the claims:

- `iss` — parent agent
- `sub` — delegate (sub-agent)
- `exp` — expiry
- `allowed_actions` — e.g. `["ToolCall::send_email"]`
- `resource_patterns` — glob patterns like `Mailbox::*`

Tokens are Ed25519-signed. The verifier checks signature, expiry, and scope.

## Production flow

1. Persist the parent agent's signing key: `agentguard delegate --key-file parent.key ...`
2. Publish the corresponding public key: `parent.pub` (`AgentKeyPub=base64...`)
3. The sub-agent presents the token alongside each request
4. The verifier runs: `agentguard verify <token> --keys parent.pub`

For the demo, we use an ephemeral key so verification isn't shown — see the
output of `python main.py` for the token format.
# Policy authoring

Policies are Cedar source files evaluated by the AgentGuard authorization
engine. A policy should make the principal, action, resource, and trusted
context explicit. The default outcome is deny: no matching permit is not an
error, it is an authorization decision.

## Authoring loop

1. Define entities and actions in the schema.
2. Write the narrowest permit needed for the tool.
3. Add explicit forbids for high-risk conditions.
4. Validate the schema and policies before deployment.
5. Replay representative allow and deny requests.
6. Review the diff and its blast-radius corpus before activation.

```sh
agentguard init --store .agentguard
agentguard validate --store .agentguard
agentguard sim --store .agentguard --request request.json
```

The CLI command is `agentguard validate`; there is no `agentguard policy`
subcommand. The standalone server is `agentguard-server`, not
`agentguard serve`.

## Safe policy shape

Prefer a permit constrained by all three identity dimensions and a trusted
fact:

```cedar
permit (
  principal == Agent::"researcher",
  action == Action::"ToolCall::repo_read",
  resource == Repository::"docs"
)
when { context.session.mfa == true };
```

Use `has` before reading optional attributes. Treat tool arguments as
untrusted input. Entity attributes and hierarchy are supplied through the
request entity set; a resource JSON object alone does not populate Cedar's
entity store.

## Activation and rollback

The standalone file watcher observes `policies/*.cedar` and
`schema.cedarschema`, builds a complete replacement authorizer, and swaps it
only after parsing succeeds. Malformed edits leave the last known-good policy
set serving. Embedded `Authorizer` values are immutable; rebuild them explicitly
when your application owns the policy lifecycle. For the standalone server,
restore the reviewed schema/policy files and restart or trigger the documented
reload path. Keep the previous bundle, decision corpus, and audit records for
the change window.

Delegation tokens describe authority but do not enforce tool scopes by
themselves. The integration at the tool boundary must verify the signature,
expiry, sender constraint, and requested scope before executing a tool.

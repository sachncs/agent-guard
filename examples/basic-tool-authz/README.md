# basic-tool-authz

The smallest possible example of agentguard in action:

1. Initialize a store
2. Add policies that say "alice can send email **only if** her session has MFA"
3. Run three different authorization requests and observe the decisions
4. Inspect the audit log

```
$ python main.py
→ Initializing agentguard store ...
→ Validating ...
Loaded 3 policies.
✓ no errors, no warnings
→ Evaluating decision: alice sending email WITHOUT MFA (should DENY) ...
{
  "effect": "deny",
  ...
}
→ Evaluating decision: alice sending email WITH MFA (should ALLOW) ...
{
  "effect": "allow",
  ...
}
```

This is what the SDK and middleware do at runtime — every tool call produces
an `AgentRequest` like the ones above, and the resulting `Decision` drives
whether the tool actually executes.
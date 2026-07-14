# nl-policy-gen

Turn natural language into Cedar policies. The CLI:

1. Reads your schema (`.agentguard/schema.cedarschema`)
2. Sends the schema + your description to an LLM with a constrained system prompt
3. Validates the output against the schema using cedar's validator
4. Writes the result to `.agentguard/policies/90_generated.cedar`

The validation step is the key loop — if the LLM produces invalid Cedar, the
generator rejects it and you can re-run with a clearer prompt.

```
$ export OPENAI_API_KEY=sk-...
$ python main.py "Only admins in the security group can rotate production secrets"
→ Generating policy ...
wrote .agentguard/policies/90_generated.cedar
--- generated policy ---
permit (
  principal in User::"admin",
  action == Action::"ToolCall::rotate_secret",
  resource
) when {
  principal.groups.contains("security")
};
→ Validating ...
Loaded 3 policies.
✓ no errors, no warnings
```
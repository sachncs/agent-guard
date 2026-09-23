# Authorization model and Cedar policies

AgentGuard evaluates a proposed operation using a principal, action, resource,
context, and any related Cedar entities. The application remains responsible
for supplying trusted facts and enforcing the result before a tool executes.

## Request model

| Input | Meaning | Example |
| --- | --- | --- |
| Principal | The authenticated user or agent. HTTP accepts `User` and `Agent`; derive it in trusted application code. | `Agent::"research"` |
| Action | The operation the tool proposes. | `Action::"ToolCall::repo_read"` |
| Resource | The object the operation would affect. Define its type in the schema. | `Repository::"demo"` |
| Context | Trusted session facts and tool arguments mapped into Cedar context. | `session.mfa: true` |

No matching permit means deny; a matching forbid overrides permits. Missing
attributes, malformed requests, and PDP failures are not permission. The
adapter must execute only when the returned decision is explicitly allow.

## Author and validate

Cedar keeps authorization rules separate from tool implementation. Use a
narrow policy tied to a principal, action, resource, and trusted conditions:

```cedar
permit (
  principal == Agent::"research",
  action == Action::"ToolCall::repo_read",
  resource == Repository::"demo"
)
when { context.session.mfa == true };
```

This example depends on the starter schema's declared request shape. Validate
policies against the schema and simulate both allow and deny cases before
deployment:

```sh
agentguard schema
agentguard validate
agentguard sim request.json
```

Schema validation is an explicit authoring step. Do not assume every server
startup performs the CLI's full validation workflow.

## Entities and trusted facts

Policies that use entity attributes or hierarchy need the corresponding Cedar
entities. The HTTP evaluation interface accepts an `entities` array and the
CLI accepts `--entities`; request resource attributes alone do not populate
the entity store. The quickstart's ID-and-context rule does not need extra
entities.

Derive identity, MFA, ownership, tenant isolation, and environment from trusted
systems. Caller-controlled context must not be treated as verified identity.
The server binds tenant metadata to an authenticated API-key identity, but
tenant metadata is not automatically a Cedar policy attribute. Encode tenant
isolation explicitly in trusted entities or context.

## Policy operations and activation scope

The `agentguard-policy` Rust library provides `PolicyBundle`, `BundleRegistry`,
disk serialization, and version lookup. `diff_bundles` compares policy
sources; `blast_radius::analyze` replays a caller-supplied corpus, so its
coverage is only as complete as that corpus.

There is no `agentguard policy` CLI command. A rollback means restoring the
selected prior schema and policy files, then allowing the standalone server to
reload or rebuilding the embedded authorizer. Version lookup does not activate
a bundle in the server.

## Watcher and reload behavior

The standalone filesystem watcher and Unix SIGHUP handler build a complete
replacement authorizer and swap it only after the policy store parses
successfully. In-flight requests keep their original snapshot. Malformed edits
leave the last known-good policies serving and emit an error. Embedded
`Authorizer` values are immutable; the embedding application owns rebuilding
and replacing them.

## Decision cache

`Authorizer::with_cache` enables an in-memory LRU/TTL decision cache. The
standalone server enables it by default. Defaults are 10,000 entries, 60
seconds for allows, and 5 seconds for denies. Cache keys include the complete
request, canonicalized Cedar entity set, and policy version so a changed
identity, context, entity, or hierarchy cannot reuse a prior decision.

The server parses `AGENTGUARD_CACHE_TTL`, `AGENTGUARD_DENY_CACHE_TTL`, and
`AGENTGUARD_CACHE_CAPACITY` with `DecisionCache::try_config_from_env`. Invalid
values fail startup rather than silently selecting different operating
limits. Embedded callers can use `Authorizer::try_with_cache` and
`DecisionCache::try_new` to receive configuration errors instead of panics;
cache use remains opt-in for embedded authorizers.

References: [authorizer implementation](../crates/agentguard-core/src/authorize/engine.rs),
[cache implementation](../crates/agentguard-core/src/decision/cache.rs),
[standalone server lifecycle](../crates/agentguard-server/src/server.rs), and
[starter schema](../schemas/starter.cedarschema).

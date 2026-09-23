# API and reference map

This page is the stable entry point for the public interfaces. The canonical
documentation site's API page links to Rustdoc generated from the exact source
revision being deployed, plus generated TypeScript declarations, CLI help, and
protobuf source/descriptor artifacts. HTTP and configuration contracts remain
in the versioned guides linked below.

| Surface | Reference | Scope |
| --- | --- | --- |
| Rust engine | [`agentguard-core`](../crates/agentguard-core/src/lib.rs) | typed requests, decisions, caching, delegation primitives |
| Rust policy | [`agentguard-policy`](../crates/agentguard-policy/src/lib.rs) | bundles, versions, diffs, blast-radius analysis |
| Rust server | [`agentguard-server`](../crates/agentguard-server/src/lib.rs) | HTTP/gRPC adapters and configuration |
| TypeScript SDK | [`typescript/agentguard`](../typescript/agentguard/src/index.ts) | CLI-backed Node.js client with synchronous and asynchronous methods |
| CLI | [`agentguard-cli`](../crates/agentguard-cli/src/main.rs) | authoring, simulation, audit, delegation, diagnostics |
| HTTP | [`authzen.rs`](../crates/agentguard-server/src/authzen.rs) | AuthZEN-compatible evaluation and batch evaluation |
| gRPC/protobuf | [`agentguard.proto`](../crates/agentguard-server/proto/agentguard.proto) | repository-defined loopback transport |
| Configuration | [`configuration`](https://sachncs.github.io/agent-guard/docs/configuration/) | binary, library, console, and Kubernetes settings |

Generate and validate the reference surfaces locally with:

```sh
cargo doc --workspace --no-deps --open
pnpm --filter agentguard build
protoc --descriptor_set_out=/tmp/agentguard.pb \
  --include_imports \
  crates/agentguard-server/proto/agentguard.proto
```

Release CI checks Rustdoc and protobuf generation without opening a browser.
The site deployment rebuilds Rustdoc, TypeScript declarations, CLI help, and
the protobuf descriptor whenever relevant workspace sources or toolchain
inputs change, then publishes them with the matching documentation revision.
HTTP clients should treat
non-2xx responses, malformed responses, timeouts, and `decision: false` as
non-execution conditions. The repository-defined gRPC endpoint is plaintext
unless the embedding deployment supplies a protected network boundary; it is
not a standardized AuthZEN gRPC protocol.

The SDK's synchronous CLI methods block the calling thread and should not be
used from concurrent web-server handlers. Use `Client.authorizeAsync` or
`Client.checkAsync` for non-blocking authorization, `Client.logTailAsync` for
audit reads, and `Client.delegateAsync` for delegation. Async operations have
a configurable timeout and bounded output. They also cap concurrent CLI
children per `Client`; saturation fails fast with `CLIUnavailable` so callers
can return a service-unavailable response instead of accumulating unbounded
child processes.

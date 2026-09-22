# API and reference map

This page is the stable entry point for the public interfaces. Generated
artifacts are produced from the checked-in source at release time; examples in
this repository are the compatibility fixtures.

| Surface | Reference | Scope |
| --- | --- | --- |
| Rust engine | [`agentguard-core`](../crates/agentguard-core/src/lib.rs) | typed requests, decisions, caching, delegation primitives |
| Rust policy | [`agentguard-policy`](../crates/agentguard-policy/src/lib.rs) | bundles, versions, diffs, blast-radius analysis |
| Rust server | [`agentguard-server`](../crates/agentguard-server/src/lib.rs) | HTTP/gRPC adapters and configuration |
| TypeScript SDK | [`typescript/agentguard`](../typescript/agentguard/src/index.ts) | CLI-backed Node.js authorization client |
| CLI | [`agentguard-cli`](../crates/agentguard-cli/src/main.rs) | authoring, simulation, audit, delegation, diagnostics |
| HTTP | [`authzen.rs`](../crates/agentguard-server/src/authzen.rs) | AuthZEN-compatible evaluation and batch evaluation |
| gRPC/protobuf | [`agentguard.proto`](../crates/agentguard-server/proto/agentguard.proto) | repository-defined loopback transport |
| Configuration | [`configuration`](https://sachncs.github.io/agent-guard/docs/configuration/) | binary, library, console, and Kubernetes settings |

Generate local Rust API documentation with:

```sh
cargo doc --workspace --no-deps --open
```

The TypeScript package is built with `pnpm --filter agentguard build`; its
declarations are emitted from the package source. HTTP clients should treat
non-2xx responses, malformed responses, timeouts, and `decision: false` as
non-execution conditions. The repository-defined gRPC endpoint is plaintext
unless the embedding deployment supplies a protected network boundary; it is
not a standardized AuthZEN gRPC protocol.

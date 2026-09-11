# rust-embedder

Mount the [AuthZEN PDP](../../docs/architecture.md) inside an existing
axum application via `agentguard_server::build_router`. Demonstrates
the embedder-facing library surface — `ServerConfig`, `Listener`,
`AuthConfig`, and `build_router` — alongside a couple of application
routes so PDP and app share a single listener.

## Run it

```sh
# 1. Initialize a policy store
cargo install --path ../../crates/agentguard-cli
agentguard init --name acme

# 2. Start the embedder (defaults to http://127.0.0.1:8443)
cargo run -p rust-embedder

# 3. Hit the application routes
curl -s http://127.0.0.1:8443/healthz
curl -s http://127.0.0.1:8443/version

# 4. Hit the nested PDP routes
curl -s http://127.0.0.1:8443/access/v1/health
```

The example nests the PDP router under `/access/v1` so a single listener
serves both application routes and the AuthZEN `evaluation` endpoint.

## Configuration

| Env var             | Purpose                          | Default                  |
| ------------------- | -------------------------------- | ------------------------ |
| `RUST_LOG`          | tracing filter                   | `info,rust_embedder=info` |

Policy store and audit log paths are hard-coded for brevity — see
`crates/agentguard-server/src/lib.rs` for the full embedder surface.

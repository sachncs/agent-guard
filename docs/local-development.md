# Local development

This guide is the supported contributor setup for AgentGuard. It keeps the
Rust workspace, TypeScript workspace, console, and documentation site on the
same pinned toolchain used by CI.

## Prerequisites

- Rust 1.89, with `rustfmt` and `clippy`
- Node.js 22.19.0 or a compatible Node.js 22.12+ runtime (Astro 7 requires it)
- pnpm 11.22.x (the bootstrap uses Corepack when available, or npm to invoke
  the pinned release when Corepack is absent)
- Protocol Buffers compiler (`protoc`) for the optional SPIFFE feature and
  protobuf descriptor checks
- Docker for image and Kubernetes smoke tests

The server build uses `protoc-bin-vendored`, but the optional SPIFFE dependency
uses `protoc` for its generated Workload API client. Set `PROTOC` to an
executable path if the compiler is not on `PATH`.

Run the checked-in bootstrap script from a clean checkout:

```sh
./scripts/setup.sh
```

The script is intentionally additive: it installs missing toolchain
components, but does not rewrite policy, audit, or user files.

## Daily commands

```sh
pnpm install --frozen-lockfile
pnpm audit:dependencies
cargo test --workspace
pnpm check
pnpm build
```

Before opening a pull request, run the same focused checks as CI:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
pnpm --filter frontend test
pnpm --filter frontend exec node scripts/e2e.mjs
```

Use `pnpm --dir site check && pnpm --dir site build` when changing the
documentation site. The root `pnpm check` also verifies public names,
repository links, and Kubernetes manifests.

## Working safely

Keep local state under `.agentguard/` or a temporary directory. Never commit
real issuer credentials, session secrets, delegation keys, chain secrets, or
audit data. Use the mock identity provider in `frontend/scripts/e2e.mjs` for
console tests. Use `cargo test --workspace --all-features` when changing
authentication or transport code because SPIFFE adds generated protobuf code.

## Architecture boundaries

The Rust crates are the policy and enforcement core. The HTTP/gRPC server is a
transport adapter, the CLI is an operator adapter, and the console is a
separate presentation layer. Keep configuration parsing at the adapter
boundary; library callers should receive explicit typed configuration rather
than reading process environment implicitly. See [architecture](architecture.md)
and the [ADR index](adr/).

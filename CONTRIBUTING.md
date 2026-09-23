# Contributing to AgentGuard

Thanks for your interest in AgentGuard. This document explains how to set up
the project locally, run the test suite, and submit a pull request.

## Reporting issues

Open an issue at
[`sachncs/agent-guard/issues`](https://github.com/sachncs/agent-guard/issues)
using the appropriate template (`bug`, `feature_request`, or `question` via
Discussions if enabled). For security issues, follow
[`SECURITY.md`](./SECURITY.md).

## Development setup

From a clean checkout, run `./scripts/setup.sh`. It installs the pinned Rust
and pnpm toolchains, verifies `protoc`, and installs both the root and Astro
site lockfiles. Copy `frontend/.env.example` to `frontend/.env.local` when
running the console locally.

The workspace declares `rust-version = "1.89"` in `[workspace.package]`,
and `rust-toolchain.toml` pins Rust 1.89.0. The setup script installs that
toolchain with `rustfmt` and `clippy`; install `protobuf-compiler` (or set
`PROTOC`) for all-feature SPIFFE builds and descriptor checks. CI verifies the
MSRV. Use only stable APIs available in 1.89; if you need a newer one, bump
`rust-version` and the pinned toolchain in the same change.

## Tests

```
cargo test --workspace
cargo test --workspace --all-features
pnpm --filter frontend test
pnpm --dir site test
```

## Lint / format

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
pnpm check
pnpm build
```

For the console production-build auth and PDP integration flow, run
`pnpm --filter frontend exec node scripts/e2e.mjs` (Docker is required).

## Pull request flow

1. Fork the repository.
2. Create a topic branch off `master` (use linear history).
3. Make focused commits with clear messages.
4. Ensure `tests`, `lint`, and `format` all pass.
5. Use the [PR template](./.github/PULL_REQUEST_TEMPLATE.md).
6. Push the branch and open a pull request targeting `master`.

By submitting a pull request, you agree to follow the
[Code of Conduct](./CODE_OF_CONDUCT.md).

# Contributing to agent-guard

Thanks for your interest in agent-guard. This document explains how to set up
the project locally, run the test suite, and submit a pull request.

## Reporting issues

Open an issue at
[`sachncs/agent-guard/issues`](https://github.com/sachncs/agent-guard/issues)
using the appropriate template (`bug`, `feature_request`, or `question` via
Discussions if enabled). For security issues, follow
[`SECURITY.md`](./SECURITY.md).

## Development setup

```
rustup toolchain install stable
```

The workspace declares `rust-version = "1.89"` in `[workspace.package]`.
CI verifies the workspace builds under that toolchain (see the `msrv`
job in `.github/workflows/ci.yml`). Use only stable APIs available in
1.89; if you need a newer one, bump `rust-version` in the same commit
and add a CHANGELOG entry.

## Tests

```
cargo test --workspace
```

## Lint / format

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Pull request flow

1. Fork the repository.
2. Create a topic branch off `master` (use linear history).
3. Make focused commits with clear messages.
4. Ensure `tests`, `lint`, and `format` all pass.
5. Use the [PR template](./.github/PULL_REQUEST_TEMPLATE.md).
6. Push the branch and open a pull request targeting `master`.

By submitting a pull request, you agree to follow the
[Code of Conduct](./CODE_OF_CONDUCT.md).

# Fuzz targets

This directory contains `cargo-fuzz` harnesses for the
agentguard-core crate. The harnesses are plain Rust binaries that
can be run with `cargo fuzz` (after `cargo install cargo-fuzz`).

To run the harnesses:

```bash
# 20-second quick check on all targets
cargo fuzz run hash_chain_append -- -max_total_time=20
cargo fuzz run canonical_json -- -max_total_time=20
cargo fuzz run glob_match -- -max_total_time=20

# Overnight (recommended for CI): 1 hour per target
cargo fuzz run hash_chain_append -- -max_total_time=3600
```

## Targets

- `hash_chain_append` — Self-verifying round-trip: append arbitrary
  bytes, then `verify()` must accept. Catches regressions in the
  HMAC construction. (The previous recursive implementation had a
  stack-overflow corner case on deep chains; the new iterative
  walk should be bulletproof.)
- `canonical_json` — Round-trip between `canonical_json()` (allocating)
  and `write_canonical_value()` (streaming). Catches any divergence
  between the two code paths.
- `glob_match` — Resource pattern matching for delegation tokens.
  Catches backtracking blowup, off-by-one bugs in segment matching.

## Why these targets?

The previous production-readiness audit found two critical bypasses
in `HashChain::append` (commit `c65b5cb`) and one in `OIDC::discover`
(commit `c65b5cb`). Fuzzing these hot paths reduces the chance of
similar regressions landing in the future.

The `cargo-deny advisories` step in CI (see `.github/workflows/`)
will check for any new advisories. The `cargo fuzz` step is NOT
in CI by default (fuzzing is slow and is opt-in) but the harnesses
exist so a developer can run them locally before any change that
touches the chain / canonical / glob code paths.

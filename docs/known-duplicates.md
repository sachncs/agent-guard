# Known duplicate crates in Cargo.lock

`cargo tree -d` reports multiple versions of several transitive
dependencies. This document explains why each one is unavoidable
without forking an upstream crate, and the operator-facing risk
(if any).

| Crate | Versions | Source | Action |
|-------|----------|--------|--------|
| `axum` | 0.6.x + 0.7.x | cedar-policy 4.11 pulls `tower`/`axum-core` 0.6 transitively for its policy-formatter lalrpop build; `axum-server` 0.7 pulls axum 0.7 | Document; pin both. Resolves when cedar-policy bumps its formatter. |
| `lalrpop` | 0.22.x | cedar-policy-core build dep + cedar-policy formatter | Same root cause. |
| `itertools` | 0.10.x + 0.14.x | cedar-policy (0.14) + rest of the graph (0.10) | Same root cause. |
| `bit-set`, `bit-vec`, `getrandom`, `rand`, `rand_chacha`, `rand_core`, `hashbrown`, `indexmap`, `either`, `digest`, `crypto-common`, `memchr`, `log`, `regex`, `regex-automata`, `smallvec`, `lalrpop-util`, `unicode-width` | (2 versions) | Conflicting transitive requirements from cedar-policy + reqwest + serde stack | Document; cannot unify without forking. |

**Why we don't `multiple-versions = "deny"`:**
deny.toml currently allows multiple versions (warn, not fail). Forcing
uniqueness would require either forking cedar-policy or pinning every
graph dependency to the version cedar-policy expects — both moves are
out of scope for the v0.2.0 hardening pass.

**Audit surface:**
Duplicate crates inflate the dependency graph and the
cargo-audit/RustSec scan time, but do not by themselves widen the
attack surface (each crate is audited independently). When
cedar-policy bumps its cedar-policy-core dependency, the duplicates
will collapse naturally.

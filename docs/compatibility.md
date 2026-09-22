# Compatibility policy

## Current support matrix

| Surface | Supported baseline |
| --- | --- |
| Rust | 1.89 MSRV; stable toolchain recommended |
| Node.js | 20.9+; Node 22 recommended |
| pnpm | 11.22.x |
| Kubernetes | 1.28+ recommended; Kustomize v5 |
| License | Apache-2.0 |

The HTTP interface follows the repository's AuthZEN request model. The gRPC
interface is repository-defined and is not presented as a standardized AuthZEN
gRPC protocol.

## Versioning

AgentGuard follows Semantic Versioning for released crates, the TypeScript SDK,
CLI behavior, and documented HTTP contracts. Breaking API or configuration
changes require a major version, a changelog entry, migration notes, and a
deprecation period where practical.

The project is pre-1.0: compatibility guarantees are best-effort until the v1.0
contract is published. Security fixes target the latest release only.
